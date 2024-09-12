<?php

require "vendor/autoload.php";

use PhpParser\NodeTraverser;
use PhpParser\ParserFactory;
use PhpParser\NodeVisitor\ParentConnectingVisitor;
use PhpParser\PrettyPrinter;
use PhpParser\NodeVisitorAbstract;
use PhpParser\Node;
use PhpParser\NodeReplacer;

function loadConfig($configFile) {
    $configData = file_get_contents($configFile);
    return json_decode($configData, true);
}

class CallGraphVisitor extends NodeVisitorAbstract {
    private $execCallers;
    private $astMap;
    private $fileName;
    public $callGraph;

    public function __construct($execCallers, $callGraph, $fileName, $astMap) {
        $this->execCallers = $execCallers;
        $this->fileName = $fileName;
        $this->astMap = $astMap;
        $this->callGraph = $callGraph;

        foreach ($execCallers as $caller) {
            list($file, $class, $method) = explode(":", $caller);
            $key = $class ? "$class::$method" : $method;
            $key = $file . "::" . $key;
            if (!array_key_exists($key, $this->callGraph)) {
               $this->callGraph[$key] = [];
            }
        }
    }

    public function enterNode(Node $node) {
        if ($node instanceof PhpParser\Node\Stmt\Function_ || $node instanceof PhpParser\Node\Stmt\ClassMethod) {
            $functionName = $this->getFunctionName($node);
            if (isset($this->callGraph[$this->fileName . "::" . $functionName])) {
                $this->findCallers($node, $functionName);
            }
        }
    }

    private function getFunctionName($node) {
        if ($node instanceof PhpParser\Node\Stmt\Function_) {
            $functionName = $node->name->toString();
            return $functionName;
        } elseif ($node instanceof PhpParser\Node\Stmt\ClassMethod) {
            $class = $node->getAttribute('parent')->name->toString();
            $methodName = $node->name->toString();
            $key = "$class::$methodName";
            return $key;
        }
        return '';
    }

    private function findCallers(Node &$node, $functionName) {
        foreach ($this->astMap as $fileName=>$ast) {
            $traverser = new NodeTraverser();
            $finder = new class($functionName, $fileName) extends NodeVisitorAbstract {
                public $functionName;
                public $foundCallers = [];
                public $fileName;

                public function __construct($functionName, $fileName) {
                    $this->functionName = $functionName;
                    $this->fileName = $fileName;
                }

                public function enterNode(Node $node) {
                    if ($node instanceof PhpParser\Node\Expr\FuncCall || $node instanceof PhpParser\Node\Expr\MethodCall) {
                        $calledFunction = $this->getFunctionName($node);
                        if ($calledFunction === $this->functionName) {
                            $caller = $this->findCaller($node);
                            if ($caller !== null) {
                                $this->foundCallers[] = $caller;
                            }
                        }
                    }
                }

                private function getFunctionName($node) {
                    if ($node instanceof PhpParser\Node\Expr\FuncCall) {
                        $functionName = $node->name instanceof PhpParser\Node\Name ? $node->name->toString() : '';
                        return $functionName;
                    } elseif ($node instanceof PhpParser\Node\Expr\MethodCall) {
                        $var = $node->var;
                        if ($var instanceof PhpParser\Node\Expr\Variable) {
                            $className = $this->findClassName($var);
                            $methodName = $node->name->toString();
                            $key = "$className::$methodName";
                            return $key;
                        } elseif ($var instanceof PhpParser\Node\Expr\PropertyFetch) {
                            $className = $this->resolvePropertyFetch($var);
                            $methodName = $node->name->toString();
                            $key = "$className::$methodName";
                            return $key;
                        }
                    }
                    return "";
                }

                function getMethodName($node) {
                    if ($node instanceof PhpParser\Node\Identifier) {
                        return $node->name;
                    } elseif ($node instanceof PhpParser\Node\Name) {
                        return implode('\\', $node->parts);
                    } elseif ($node instanceof PhpParser\Node\Expr\Variable) {
                        return '$' . $node->name;
                    }
                    return '';
                }

                private function findClassName($node) {
                    while ($node !== null) {
                        if ($node instanceof PhpParser\Node\Stmt\Class_) {
                            return $node->name->toString();
                        }
                        $node = $node->getAttribute('parent');
                    }
                    return 'unknown_class';
                }

                private function resolvePropertyFetch($node) {
                    $class = $node->var;
                    while ($class !== null) {
                        if ($class instanceof PhpParser\Node\Expr\Variable) {
                            return $this->findClassName($class);
                        }
                        $class = $class->getAttribute('parent');
                    }
                    return 'unknown_class';
                }

                private function findCaller(Node &$node) {
                    $parent = $node->getAttribute('parent');
                    while ($parent !== null) {
                        if ($parent instanceof PhpParser\Node\Stmt\Function_ || $parent instanceof PhpParser\Node\Stmt\ClassMethod) {
                            return $parent;
                        }
                        $parent = $parent->getAttribute('parent');
                    }
                    return null;
                }
            };

            $traverser->addVisitor(new ParentConnectingVisitor());
            $traverser->addVisitor($finder);
            $traverser->traverse($ast);

            foreach ($finder->foundCallers as $caller) {
                $callerName = $this->getFunctionName($caller);
                if (!in_array($callerName, $this->callGraph[$fileName . "::" . $functionName])) {
                    $this->callGraph[$fileName . "::" . $functionName][] = $callerName;
                }
                $this->findCallers($caller, $callerName);
            }
        }
    }

    public function getCallGraph() {
        return $this->callGraph;
    }
}


class ReversePathFinder {
    private $callGraph;
    private $sinkFunctions;
    private $reversePaths = [];

    public function __construct($callGraph, $sinkFunctions) {
        $this->callGraph = $callGraph;
        $this->sinkFunctions = $sinkFunctions;
    }

    public function findReversePaths() {
        foreach ($this->sinkFunctions as $sink) {
            foreach ($this->callGraph as $functionNode => $callees) {
                if ($functionNode == $sink) {
                    $this->dfs($functionNode, []);
                }
            }
        }
        return $this->reversePaths;
    }

    private function dfs($currentFunction, $path) {
        $path[] = $currentFunction;
        $callers = $this->findCallers($currentFunction);

        if (empty($callers)) {
            $this->reversePaths[] = array_reverse($path);
        } else {
            foreach ($callers as $caller) {
                $this->dfs($caller, $path);
            }
        }
    }

    private function findCallers($functionName) {
        $callers = [];
        foreach ($this->callGraph as $caller => $callees) {
            if (in_array($functionName, $callees)) {
                $callers[] = $caller;
            }
        }
        return $callers;
    }
}

class InstrumenterVisitor extends NodeVisitorAbstract {
    private $fileName;
    private $reversePaths;
    private $instrumentedMethods;
    private $ip;
    private $port;

    function __construct($fileName, $reversePaths, &$instrumentedMethods, $ip, $port) {
        $this->fileName = $fileName;
        $this->reversePaths = $reversePaths;
        $this->instrumentedMethods = $instrumentedMethods;
        $this->ip = $ip;
        $this->port = $port;
    }

    public function leaveNode(Node $node) {
        if ($node instanceof PhpParser\Node\Stmt\Function_ || $node instanceof PhpParser\Node\Stmt\ClassMethod) {
            $type = 'COMPLETE';
            if ($this->isSink($node)) {
                $type = 'SINK';
            } elseif ($this->isIntermediate($node)) {
                $type = 'INTERMEDIATE';
            }

            if ($this->isInstrumented($node)) {
                return $node;
            }

            $this->instrumentedMethods[] = $node;
            $this->insertInstrumentation($node, $type);
        }
        return $node;
    }

    private function insertInstrumentation(Node &$node, $type) {
        $timeVar = new PhpParser\Node\Expr\Variable('time_var');
        $assignment = new PhpParser\Node\Stmt\Expression(new PhpParser\Node\Expr\Assign($timeVar, new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('time'))));
        $message = new PhpParser\Node\Expr\BinaryOp\Concat($timeVar, new PhpParser\Node\Scalar\String_(" $type " . $this->getFunctionName($node) . "<LINE>" . $node->getLine() ."</LINE>"));

        $fp = new PhpParser\Node\Expr\Variable('fp');
        $fsockopen = new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('fsockopen'), [
            new PhpParser\Node\Arg(new PhpParser\Node\Scalar\String_($this->ip)),
            new PhpParser\Node\Arg(new PhpParser\Node\Scalar\LNumber($this->port))
        ]);

        $assignmentFp = new PhpParser\Node\Stmt\Expression(new PhpParser\Node\Expr\Assign($fp, $fsockopen));
        $fwrite = new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('fwrite'), [
            new PhpParser\Node\Arg($fp),
            new PhpParser\Node\Arg($message)
        ]);
        $fclose = new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('fclose'), [
            new PhpParser\Node\Arg($fp)
        ]);

        $statements = [$assignmentFp,
                       new PhpParser\Node\Stmt\Expression($fwrite), 
                       new PhpParser\Node\Stmt\Expression($fclose)
                      ];

        array_unshift($node->stmts, $assignment, ...$statements);
    }

    private function isInstrumented(Node &$node) {
        foreach ($this->instrumentedMethods as $instrumentedMethod) {
            if ($instrumentedMethod === $node) {
                return true;
            }
        }
        return false;
    }

    private function isSink(Node &$node) {
        if (isset($node->stmts)) {
            foreach ($node->stmts as $stmt) {
                if ($stmt instanceof PhpParser\Node\Stmt\Expression && $stmt->expr instanceof PhpParser\Node\Expr\FuncCall) {
                    $funcName = $stmt->expr->name instanceof PhpParser\Node\Name ? $stmt->expr->name->toString() : '';
                    if (in_array($funcName, ['exec', 'passthru', 'shell_exec', 'system'])) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private function isIntermediate(Node &$node) {
        $functionName = $this->getFunctionNameCallGraph($node);
        foreach ($this->reversePaths as $sink => $paths) {
            foreach ($paths as $path) {
                if (in_array($functionName, $path)) {
                    return true;
                }
            }
        }
        return false;
    }

    private function getFunctionNameCallGraph($node) {
        if ($node instanceof PhpParser\Node\Stmt\Function_) {
            return $this->fileName . "::" . $node->name->toString();
        } elseif ($node instanceof PhpParser\Node\Stmt\ClassMethod) {
            $class = $node->getAttribute('parent')->name->toString();
            return $this->fileName . "::" . $class . "::" . $node->name->toString();
        }
        return "";
    }

    private function getFunctionName($node) {
        if ($node instanceof PhpParser\Node\Stmt\Function_) {
            return "<TYPE>function</TYPE><FILE>" . $this->fileName . "</FILE><NAME>" . $node->name->toString() . "</NAME>";
        } elseif ($node instanceof PhpParser\Node\Stmt\ClassMethod) {
            $class = $node->getAttribute('parent')->name->toString();
            return "<TYPE>method</TYPE><FILE>" . $this->fileName . "</FILE><NAME>" . $node->name->toString() . "</NAME><CLASS>" . $class . "</CLASS>";
        }
        return "<TYPE>script</TYPE><FILE>{$this->fileName}</FILE><NAME>global-scope</NAME>";
    }
}

class GlobalInstrumenterVisitor extends NodeVisitorAbstract {
    private $fileName;
    private $ip;
    private $port;

    function __construct($fileName, $ip, $port) {
        $this->fileName = $fileName;
        $this->ip = $ip;
        $this->port = $port;
    }

    public function beforeTraverse(array $nodes) {
        return $this->insertInstrumentation($nodes);
    }

    private function insertInstrumentation(array &$nodes) {
        $timeVar = new PhpParser\Node\Expr\Variable('time_var');
        $assignment = new PhpParser\Node\Stmt\Expression(new PhpParser\Node\Expr\Assign($timeVar, new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('time'))));
        $message = new PhpParser\Node\Expr\BinaryOp\Concat($timeVar, new PhpParser\Node\Scalar\String_(" SCRIPT <TYPE>script</TYPE><FILE>{$this->fileName}</FILE><NAME>global-scope</NAME>"));

        $fp = new PhpParser\Node\Expr\Variable('fp');
        $fsockopen = new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('fsockopen'), [
            new PhpParser\Node\Arg(new PhpParser\Node\Scalar\String_($this->ip)),
            new PhpParser\Node\Arg(new PhpParser\Node\Scalar\LNumber($this->port))
        ]);

        $assignmentFp = new PhpParser\Node\Stmt\Expression(new PhpParser\Node\Expr\Assign($fp, $fsockopen));
        $fwrite = new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('fwrite'), [
            new PhpParser\Node\Arg($fp),
            new PhpParser\Node\Arg($message)
        ]);
        $fclose = new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('fclose'), [
            new PhpParser\Node\Arg($fp)
        ]);

        $statements = [$assignmentFp,
                       new PhpParser\Node\Stmt\Expression($fwrite), 
                       new PhpParser\Node\Stmt\Expression($fclose)
                      ];

        return array_merge($statements, $nodes);
    }
}

class IfReturnInstrumenterVisitor extends NodeVisitorAbstract {
    private $fileName;
    private $ip;
    private $port;

    function __construct($fileName, $ip, $port) {
        $this->fileName = $fileName;
        $this->ip = $ip;
        $this->port = $port;
    }

    public function beforeTraverse(array $nodes) {
        foreach ($nodes as $node) {
            if ($node instanceof PhpParser\Node\Stmt\If_) {
                $this->insertIfInstrumentation($node);
            }
        }
        return $nodes;
    }

    public function leaveNode(Node $node) {
        if ($node instanceof PhpParser\Node\Stmt\If_) {
            $this->insertIfInstrumentation($node);
        } else if (isset($node->stmts)) {
            foreach($node->stmts as $stmt) {
                if ($stmt instanceof PhpParser\Node\Stmt\Return_) {
                    $this->insertReturnInstrumentation($node, $stmt);
                }
            }
        }
        return $node;
    }

    private function insertIfInstrumentation(Node &$node) {
        $methodString = $this->getMethodString($node);
        $statements = $this->get_instrumented_statements($node, $methodString, 'IF');
        $this->replaceNodeWithStatements($node, $statements);
    }

    private function insertReturnInstrumentation(Node &$parent, Node &$node) {
        $methodString = $this->getMethodString($node);
        $statements = $this->get_instrumented_statements($node, $methodString, 'RETURN');
        $this->replaceNodeWithStatementsParent($parent, $node, $statements);
    }

    private function get_instrumented_statements(Node &$node, $message, $type) {
        $timeVar = new PhpParser\Node\Expr\Variable('time_var');
        $assignment = new PhpParser\Node\Stmt\Expression(new PhpParser\Node\Expr\Assign($timeVar, new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('time'))));
        $logMessage = new PhpParser\Node\Expr\BinaryOp\Concat($timeVar, new PhpParser\Node\Scalar\String_(" $type " . trim($message) . "<LINE>" . $node->getLine() ."</LINE>"));

        $fp = new PhpParser\Node\Expr\Variable('fp');
        $fsockopen = new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('fsockopen'), [
            new PhpParser\Node\Arg(new PhpParser\Node\Scalar\String_($this->ip)),
            new PhpParser\Node\Arg(new PhpParser\Node\Scalar\LNumber($this->port))
        ]);

        $assignmentFp = new PhpParser\Node\Stmt\Expression(new PhpParser\Node\Expr\Assign($fp, $fsockopen));
        $fwrite = new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('fwrite'), [
            new PhpParser\Node\Arg($fp),
            new PhpParser\Node\Arg($logMessage)
        ]);
        $fclose = new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('fclose'), [
            new PhpParser\Node\Arg($fp)
        ]);

        $statements = [
            $assignment,
            $assignmentFp,
            new PhpParser\Node\Stmt\Expression($fwrite),
            new PhpParser\Node\Stmt\Expression($fclose)
        ];
        return $statements;
    }

    private function replaceNodeWithStatements(Node &$parent, array $statements) {
        array_unshift($parent->stmts, ...$statements);
    }


    private function replaceNodeWithStatementsParent(Node &$parent, Node &$node, array $statements) {
        foreach ($parent->stmts as $key => $stmt) {
            if ($stmt === $node) {
                array_splice($parent->stmts, $key, 1, $statements);
                foreach ($statements as $stmt) {
                    $stmt->setAttribute('parent', $parent);
                }
                return;
            }
        }
    }

    private function getMethodString(Node &$node) {
        $method = $node;
        while ($method && !($method instanceof PhpParser\Node\Stmt\ClassMethod || $method instanceof PhpParser\Node\Stmt\Function_)) {
            $method = $method->getAttribute('parent');
        }
        if ($method instanceof PhpParser\Node\Stmt\ClassMethod) {
            $class = $method->getAttribute('parent');
            return "<TYPE>method</TYPE><FILE>{$this->fileName}</FILE><NAME>{$method->name}</NAME><CLASS>{$class->name}</CLASS>";
        } elseif ($method instanceof PhpParser\Node\Stmt\Function_) {
            return "<TYPE>function</TYPE><FILE>{$this->fileName}</FILE><NAME>{$method->name}</NAME>";
        }
        return "<TYPE>script</TYPE><FILE>{$this->fileName}</FILE><NAME>global-scope</NAME>";
    }
}

class ExecEvalVisitor extends NodeVisitorAbstract {
    private $fileName;
    private $ip;
    private $port;
    private $outputPort;

    function __construct($fileName, $ip, $port, $outputPort) {
        $this->fileName = $fileName;
        $this->ip = $ip;
        $this->port = $port;
        $this->outputPort = $outputPort;
    }

    public function beforeTraverse(array $nodes) {
        foreach ($nodes as $stmt) {
            if ($stmt instanceof PhpParser\Node\Stmt\Expression) {
                $expr = $stmt->expr;
                $funcCallNode = null;

                if ($expr instanceof PhpParser\Node\Expr\FuncCall) {
                    $funcCallNode = $expr;
                } elseif ($expr instanceof PhpParser\Node\Expr\Assign && $expr->expr instanceof PhpParser\Node\Expr\FuncCall) {
                    $funcCallNode = $expr->expr;
                }
                if ($funcCallNode) {
                    $funcName = $funcCallNode->name instanceof PhpParser\Node\Name ? $funcCallNode->name->toString() : '';
                    if (in_array($funcName, ['exec', 'passthru', 'shell_exec', 'system'])) {
                        $this->insertInstrumentationGlobal($nodes, 'EXEC', $stmt, $funcName);
                    }
                }
            }
        }
        return $nodes;
    }

    public function leaveNode(Node $node) {
        if (isset($node->stmts)) {
            foreach ($node->stmts as $stmt) {
                if ($stmt instanceof PhpParser\Node\Stmt\Expression) {
                    $expr = $stmt->expr;
                    $funcCallNode = null;

                    if ($expr instanceof PhpParser\Node\Expr\FuncCall) {
                        $funcCallNode = $expr;
                    } elseif ($expr instanceof PhpParser\Node\Expr\Assign && $expr->expr instanceof PhpParser\Node\Expr\FuncCall) {
                        $funcCallNode = $expr->expr;
                    }
                    if ($funcCallNode) {
                        $funcName = $funcCallNode->name instanceof PhpParser\Node\Name ? $funcCallNode->name->toString() : '';
                        if (in_array($funcName, ['exec', 'passthru', 'shell_exec', 'system'])) {
                            $this->insertInstrumentation($node, 'EXEC', $stmt, $funcName);
                        }
                    }
                }
            }
        }
        return $node;
    }

    private function insertInstrumentation(Node &$node, $type, $execNode, $execType) {
        $statements = $this->get_instrumented_statements($node, $type, $execNode, $execType);
        $this->replaceNodeWithStatements($node, $execNode, $statements);
    }  
    
    private function insertInstrumentationGlobal(&$nodes, $type, $execNode, $execType) {
        $statements = $this->get_instrumented_statements($execNode, $type, $execNode, $execType);
        $this->replaceNodeWithStatementsGlobal($nodes, $execNode, $statements);
    }  

    private function get_instrumented_statements($node, $type, $execNode, $execType) {
        $methodString = $this->getMethodString($node);
        $timeVar = new PhpParser\Node\Expr\Variable('time_var');
        $assignment = new PhpParser\Node\Stmt\Expression(new PhpParser\Node\Expr\Assign(
            $timeVar, new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('time'))
        ));
    
        $message = new PhpParser\Node\Expr\BinaryOp\Concat(
            new PhpParser\Node\Expr\BinaryOp\Concat($timeVar, new PhpParser\Node\Scalar\String_(" ")),
            new PhpParser\Node\Scalar\String_("$type " . trim($methodString) . "<LINE>" . $execNode->getLine() ."</LINE>")
        );
    
        $fp = new PhpParser\Node\Expr\Variable('fp');
        $fsockopen = new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('fsockopen'), [
            new PhpParser\Node\Arg(new PhpParser\Node\Scalar\String_($this->ip)),
            new PhpParser\Node\Arg(new PhpParser\Node\Scalar\LNumber($this->port))
        ]);
        $assignmentFp = new PhpParser\Node\Stmt\Expression(new PhpParser\Node\Expr\Assign($fp, $fsockopen));
        $fwrite = new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('fwrite'), [
            new PhpParser\Node\Arg($fp),
            new PhpParser\Node\Arg($message)
        ]);
        $fclose = new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('fclose'), [
            new PhpParser\Node\Arg($fp)
        ]);
    
        $outputVar = new PhpParser\Node\Expr\Variable('output_var');
        $outputAssignStatements = $this->modifyExecCall($execNode, $outputVar, $execType);

        $outputString = new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('implode'), [
            new PhpParser\Node\Arg(new PhpParser\Node\Scalar\String_("\\n")), // Usa "\\n" per mantenere \n letterale
            new PhpParser\Node\Arg($outputVar)
        ]);
    
        $outputMessage = new PhpParser\Node\Expr\BinaryOp\Concat(
            new PhpParser\Node\Scalar\String_("OUTPUT: "),
            $outputString
        );
    
        $outputFp = new PhpParser\Node\Expr\Variable('fp_output');
        $fsockopenOutput = new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('fsockopen'), [
            new PhpParser\Node\Arg(new PhpParser\Node\Scalar\String_($this->ip)),
            new PhpParser\Node\Arg(new PhpParser\Node\Scalar\LNumber($this->outputPort))
        ]);
        $assignmentFpOutput = new PhpParser\Node\Stmt\Expression(new PhpParser\Node\Expr\Assign($outputFp, $fsockopenOutput));
        $fwriteOutput = new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('fwrite'), [
            new PhpParser\Node\Arg($outputFp),
            new PhpParser\Node\Arg($outputMessage)
        ]);
        $fcloseOutput = new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('fclose'), [
            new PhpParser\Node\Arg($outputFp)
        ]);
    
        $statements = [
            $assignment,
            $assignmentFp,
            new PhpParser\Node\Stmt\Expression($fwrite),
            new PhpParser\Node\Stmt\Expression($fclose)
        ];
    
        if (is_array($outputAssignStatements)) {
            $statements = array_merge($statements, $outputAssignStatements);
        } else {
            $statements[] = $outputAssignStatements;
        }
    
        $statements = array_merge($statements, [
            $assignmentFpOutput,
            new PhpParser\Node\Stmt\Expression($fwriteOutput),
            new PhpParser\Node\Stmt\Expression($fcloseOutput)
        ]);
        return $statements;
    }
    
    private function replaceNodeWithStatements(Node &$parent, Node &$execNode, array $statements) {
        foreach ($parent->stmts as $key => $stmt) {
            if ($stmt === $execNode) {
                array_splice($parent->stmts, $key, 1, $statements);
                foreach ($statements as $stmt) {
                    $stmt->setAttribute('parent', $parent);
                }
                return;
            }
        }
    }

    private function replaceNodeWithStatementsGlobal(&$nodes, Node &$execNode, array $statements) {
        foreach ($nodes as $key => $stmt) {
            if ($stmt === $execNode) {
                array_splice($nodes, $key, 1, $statements);
                return;
            }
        }
    }
    
    private function modifyExecCall(Node &$execNode, $outputVar, $execType) {
        switch ($execType) {
            case 'exec':
                $stmts = [];
                $funcCall = $execNode->expr;
                if ($funcCall instanceof PhpParser\Node\Expr\Assign) {
                    $funcCall = $funcCall->expr;
                }
                $existingOutputArray = null;
                if (count($funcCall->args) > 1 && $funcCall->args[1]->value instanceof PhpParser\Node\Expr\Variable) {
                    $existingOutputArray = $funcCall->args[1]->value;
                }
                if ($existingOutputArray === null) {
                    $outputArray = new PhpParser\Node\Expr\Variable('output_array');
                    $declareOutputArray = new PhpParser\Node\Stmt\Expression(new PhpParser\Node\Expr\Assign($outputArray, new PhpParser\Node\Expr\Array_([])));
                    $funcCall->args[] = new PhpParser\Node\Arg($outputArray);
                    $stmts[] = $declareOutputArray;
                    if ($execNode->expr instanceof PhpParser\Node\Expr\Assign) {
                        $execNode->expr->expr = $funcCall;
                    }
                } else {
                    $outputArray = $existingOutputArray;
                }
                $stmts[] = $execNode;
                $stmts[] = new PhpParser\Node\Stmt\Expression(new PhpParser\Node\Expr\Assign($outputVar, $outputArray));
                return $stmts;

            case 'system':
                if ($execNode->expr instanceof PhpParser\Node\Expr\Assign && $execNode->expr->var instanceof PhpParser\Node\Expr\Variable) {
                    $assignedOutputVar = $execNode->expr->var;
                } else {
                    $assignedOutputVar = new PhpParser\Node\Expr\Variable('temp_output_var');
                    $execNode->expr = new PhpParser\Node\Expr\Assign($assignedOutputVar, $execNode->expr);
                }
                $outputArray = new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('explode'), [
                    new PhpParser\Node\Arg(new PhpParser\Node\Scalar\String_("\\n")),
                    new PhpParser\Node\Arg($assignedOutputVar)
                ]);

                return [
                    new PhpParser\Node\Stmt\Expression($execNode->expr),
                    new PhpParser\Node\Stmt\Expression(new PhpParser\Node\Expr\Assign($outputVar, $outputArray))
                ];

            case 'passthru':
                $stmts = [];
                $parentNode = $execNode->getAttribute('parent');
                $obStartPresent = false;
    
                $index = array_search($execNode, $parentNode->stmts, true);
                if ($index > 0 && isset($parentNode->stmts[$index - 1])) {
                    $previousStmt = $parentNode->stmts[$index - 1];
                    if ($previousStmt instanceof PhpParser\Node\Stmt\Expression && $previousStmt->expr instanceof PhpParser\Node\Expr\FuncCall) {
                        $funcName = $previousStmt->expr->name instanceof PhpParser\Node\Name ? $previousStmt->expr->name->toString() : '';
                        if ($funcName === 'ob_start') {
                            $obStartPresent = true;
                        }
                    }
                }
                if (!$obStartPresent) {
                    $stmts[] = new PhpParser\Node\Stmt\Expression(
                        new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('ob_start'))
                    );
                }
                $stmts[] = $execNode;
    
                $outputContentsVar = null;
                $foundObEndClean = false;
    
                $startIndex = $index + 1;
                $subsequentStmts = array_slice($parentNode->stmts, $startIndex);
    
                foreach ($subsequentStmts as $stmt) {
                    if ($stmt instanceof PhpParser\Node\Stmt\Expression) {
                        $innerExpr = $stmt->expr;
                        if ($innerExpr instanceof PhpParser\Node\Expr\FuncCall) {
                            $funcName = $innerExpr->name->toString();
                            if ($funcName === 'ob_end_clean') {
                                $foundObEndClean = true;
                            }
                        } elseif ($innerExpr instanceof PhpParser\Node\Expr\Assign && $innerExpr->expr instanceof PhpParser\Node\Expr\FuncCall) {
                            $assignFuncCall = $innerExpr->expr;
                            $funcName = $assignFuncCall->name->toString();
                            if ($funcName === 'ob_get_contents') {
                                $outputContentsVar = $innerExpr->var;
                            }
                        }
                    }
                }
    
                if ($outputContentsVar === null) {
                    $outputContentsVar = new PhpParser\Node\Expr\Variable('temp_output_var');
                    $stmts[] = new PhpParser\Node\Stmt\Expression(new PhpParser\Node\Expr\Assign(
                        $outputContentsVar,
                        new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('ob_get_contents'))
                    ));
                }
    
                if (!$foundObEndClean) {
                    $stmts[] = new PhpParser\Node\Stmt\Expression(new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('ob_end_clean')));
                }
    
                $outputArray = new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('explode'), [
                    new PhpParser\Node\Arg(new PhpParser\Node\Scalar\String_("\\n")),
                    new PhpParser\Node\Arg($outputContentsVar)
                ]);
    
                $stmts[] = new PhpParser\Node\Stmt\Expression(new PhpParser\Node\Expr\Assign($outputVar, $outputArray));
                return $stmts;

            case 'shell_exec':
                $assignedOutputVar = null;
                $stmts = [];

                if ($execNode->expr instanceof PhpParser\Node\Expr\Assign && $execNode->expr->var instanceof PhpParser\Node\Expr\Variable) {
                    $assignedOutputVar = $execNode->expr->var;
                    $stmts[] = $execNode;
                } else {
                    $assignedOutputVar = new PhpParser\Node\Expr\Variable('temp_output_var');
                    $stmts[] = new PhpParser\Node\Stmt\Expression(
                        new PhpParser\Node\Expr\Assign($assignedOutputVar, $execNode->expr)
                    );
                }
                $outputArray = new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('explode'), [
                    new PhpParser\Node\Arg(new PhpParser\Node\Scalar\String_("\\n")),
                    new PhpParser\Node\Arg($assignedOutputVar)
                ]);

                $stmts[] = new PhpParser\Node\Stmt\Expression(new PhpParser\Node\Expr\Assign($outputVar, $outputArray));
                return $stmts;

            default:
                return null;
        }
    }
    
    private function getMethodString(Node &$node) {
        $method = $node;
        while ($method && !($method instanceof PhpParser\Node\Stmt\ClassMethod || $method instanceof PhpParser\Node\Stmt\Function_)) {
            $method = $method->getAttribute('parent');
        }
        if ($method instanceof PhpParser\Node\Stmt\ClassMethod) {
            $class = $method->getAttribute('parent');
            return "<TYPE>method</TYPE><FILE>{$this->fileName}</FILE><NAME>{$method->name}</NAME><CLASS>{$class->name}</CLASS>";
        } elseif ($method instanceof PhpParser\Node\Stmt\Function_) {
            return "<TYPE>function</TYPE><FILE>{$this->fileName}</FILE><NAME>{$method->name}</NAME>";
        }
        return "<TYPE>script</TYPE><FILE>{$this->fileName}</FILE><NAME>global-scope</NAME>";
    }
}


$config = loadConfig('config.json');
$ip = $config['ip_address'];
$visitorPort = $config['visitor_port'];
$execPort = $config['exec_port'];
$execFile = $config['exec-file'];
$phpFile = $config['php-files'];

$methods = fopen($execFile, "r");
$phpFiles = fopen($phpFile, "r");
$stmts = [];
$parser = (new ParserFactory)->create(ParserFactory::PREFER_PHP7);

while (($file = fgets($phpFiles)) !== false) {
    $code = file_get_contents(trim($file));
    $stmts[trim($file)] = $parser->parse($code);
}

$execCallers = [];
while (($method = fgets($methods)) !== false) {
    $execCallers[] = trim($method);
}
fclose($methods);

$callGraph = [];
foreach ($stmts as $fileName => $stmt) {
    $callGraphVisitor = new CallGraphVisitor($execCallers, $callGraph, $fileName, $stmts);
    $traverser = new NodeTraverser();
    $traverser->addVisitor(new ParentConnectingVisitor());
    $traverser->addVisitor($callGraphVisitor);
    $traverser->traverse($stmt);

    $callGraph = $callGraphVisitor->callGraph;
}

$pathFinder = new ReversePathFinder($callGraph, $execCallers);
$reversePaths = $pathFinder->findReversePaths();

$instrumentedMethods = [];
$ifNodesToInstrument = [];
$returnNodesToInstrument = [];

foreach ($reversePaths as $path) {
    foreach ($path as $node) {
        if (!in_array($node, $instrumentedMethods)) {
            $instrumentedMethods[] = $node;
        }
    }
}

foreach ($stmts as $fileName => $stmt) {
    $ifReturnInstrumenterVisitor = new IfReturnInstrumenterVisitor($fileName, $ip, $visitorPort);
    $traverser = new NodeTraverser();
    $traverser->addVisitor(new ParentConnectingVisitor());
    $traverser->addVisitor($ifReturnInstrumenterVisitor);
    $stmts[$fileName] = $traverser->traverse($stmt);

    $execEvalVisitor = new ExecEvalVisitor($fileName, $ip, $visitorPort, $execPort);
    $traverser = new NodeTraverser();
    $traverser->addVisitor(new ParentConnectingVisitor());
    $traverser->addVisitor($execEvalVisitor);
    $stmts[$fileName] = $traverser->traverse($stmts[$fileName]);

    $globalInstrumenterVisitor = new GlobalInstrumenterVisitor($fileName, $ip, $visitorPort);
    $traverser = new NodeTraverser();
    $traverser->addVisitor(new ParentConnectingVisitor());
    $traverser->addVisitor($globalInstrumenterVisitor);
    $stmts[$fileName] = $traverser->traverse($stmts[$fileName]);

    $instrumenterVisitor = new InstrumenterVisitor($fileName, $reversePaths, $instrumentedMethods, $ip, $visitorPort);
    $traverser = new NodeTraverser();
    $traverser->addVisitor(new ParentConnectingVisitor());
    $traverser->addVisitor($instrumenterVisitor);
    $stmts[$fileName] = $traverser->traverse($stmts[$fileName]);
}

$prettyPrinter = new PrettyPrinter\Standard();
foreach ($stmts as $fileName => $stmt) {
    $newFileContent = $prettyPrinter->prettyPrintFile($stmt);
    file_put_contents($fileName, $newFileContent);
}

fclose($phpFiles);
?>
