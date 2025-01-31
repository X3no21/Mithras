<?php

require "../vendor/autoload.php";

use PhpParser\NodeTraverser;
use PhpParser\ParserFactory;
use PhpParser\NodeVisitorAbstract;
use PhpParser\Node;
use PhpParser\NodeVisitor\ParentConnectingVisitor;

class FunctionDefVisitor extends NodeVisitorAbstract {
    private $file;
    public $functions;

    public function __construct($file, &$functions) {
        $this->file = $file;
        $this->functions = &$functions;
    }

    public function enterNode(Node $node) {
        if ($node instanceof PhpParser\Node\Stmt\Function_) {
            $function_name = "<NAME>{$node->name}</NAME>";
            $this->addFunction($function_name);
        } elseif ($node instanceof PhpParser\Node\Stmt\ClassMethod) {
            $class = $node->getAttribute('parent');
            $method_name = "<NAME>{$node->name}</NAME><CLASS>{$class->name}</CLASS>";
            $this->addFunction($method_name);
        }
    }

    private function addFunction($function_name) {
        if (!isset($this->functions[$this->file])) {
            $this->functions[$this->file] = [];
        }
        if (!in_array($function_name, $this->functions[$this->file])) {
            $this->functions[$this->file][] = $function_name;
        }
    }
}

class CallGraphVisitor extends NodeVisitorAbstract {
    private $file;
    private $url;
    private $functions;
    private $astMap;

    public function __construct($file, $url, $functions, $astMap) {
        $this->file = $file;
        $this->url = $url;
        $this->functions = $functions;
        $this->astMap = $astMap;
    }

    public function enterNode(Node $node) {
        if ($node instanceof PhpParser\Node\Stmt\Expression &&
            ($node->expr instanceof PhpParser\Node\Expr\FuncCall || $node->expr instanceof PhpParser\Node\Expr\MethodCall)) {
            $this->findCaller($node);
        }
    }

    private function findCaller(Node $node) {
        $node_str = $this->createNodeStr($node);
        $node_parent = $this->findParentNode($node);

        $node_parent_str = $this->createParentNodeStr($node_parent);

        if (empty($node_parent_str) || empty($node_str)) {
            echo "Skipping request: parent or child is empty. Parent: $node_parent_str, Child: $node_str\n";
            return;
        }

        $fields = [
            "parent" => $node_parent_str,
            "child" => $node_str
        ];

        $this->sendRequest($fields);
    }

    private function findParentNode(Node $node) {
        $parent = $node->getAttribute('parent');
        if ($parent !== null) {
            return $parent;
        }

        foreach ($this->astMap as $ast) {
            $traverser = new NodeTraverser;
            $finder = new class extends NodeVisitorAbstract {
                public $foundNode = null;
                public $targetNode;

                public function enterNode(Node $node) {
                    if ($node === $this->targetNode) {
                        $this->foundNode = $node->getAttribute('parent');
                    }
                }
            };

            $finder->targetNode = $node;
            $traverser->addVisitor(new ParentConnectingVisitor);
            $traverser->addVisitor($finder);
            $traverser->traverse($ast);

            if ($finder->foundNode !== null) {
                return $finder->foundNode;
            }
        }

        return null;
    }

    private function createNodeStr(Node $node) {
        if ($node->expr instanceof PhpParser\Node\Expr\MethodCall) {
            $class_node = $node->expr->var;
            $method_name = $node->expr->name->name;

            if ($class_node instanceof PhpParser\Node\Expr\Variable) {
                $class_name = $this->findClassName($class_node);
            } else if (isset($class_node->class) && is_object($class_node->class)) {
                $class_name = $class_node->class->toString();
            } else {
                $class_name = $this->findClassName($class_node);
            }

            $file_name = $this->findFileName($class_name, $method_name, 'method');
            return "<TYPE>method</TYPE><FILE>{$file_name}</FILE><NAME>{$method_name}</NAME><CLASS>{$class_name}</CLASS>";
        } elseif ($node->expr instanceof PhpParser\Node\Expr\FuncCall) {
            $funcName = $node->expr->name;
            return "<TYPE>function</TYPE><FILE>{$this->file}</FILE><NAME>{$funcName}</NAME>";
        }
        return "<TYPE>script</TYPE><FILE>{$this->file}</FILE><NAME>global-scope</NAME>";
    }

    private function findClassName($node) {
        while ($node !== null) {
            if ($node instanceof PhpParser\Node\Stmt\Class_) {
                return $node->name->toString();
            }
            $node = $node->getAttribute('parent');
        }

        foreach ($this->astMap as $ast) {
            $traverser = new NodeTraverser;
            $finder = new class extends NodeVisitorAbstract {
                public $foundClassName = null;
                public $targetNode;

                public function enterNode(Node $node) {
                    if ($node === $this->targetNode) {
                        $parentNode = $node->getAttribute('parent');
                        while ($parentNode !== null) {
                            if ($parentNode instanceof PhpParser\Node\Stmt\Class_) {
                                $this->foundClassName = $parentNode->name->toString();
                                break;
                            }
                            $parentNode = $parentNode->getAttribute('parent');
                        }
                    }
                }
            };

            $finder->targetNode = $node;
            $traverser->addVisitor(new ParentConnectingVisitor);
            $traverser->addVisitor($finder);
            $traverser->traverse($ast);

            if ($finder->foundClassName !== null) {
                return $finder->foundClassName;
            }
        }

        return 'unknown_class';
    }

    private function createParentNodeStr(?Node $node_parent) {
        if ($node_parent === null) {
            return "<TYPE>script</TYPE><FILE>{$this->file}</FILE><NAME>global-scope</NAME>";
        }

        if ($node_parent instanceof PhpParser\Node\Stmt\ClassMethod) {
            $class = $node_parent->getAttribute('parent');
            $method_name = $node_parent->name;
            $class_name = is_object($class) ? $class->name->toString() : 'unknown_class';
            $file_name = $this->findFileName($class_name, $method_name, 'method');
            return "<TYPE>method</TYPE><FILE>{$file_name}</FILE><NAME>{$method_name}</NAME><CLASS>{$class_name}</CLASS>";
        } elseif ($node_parent instanceof PhpParser\Node\Stmt\Function_) {
            $function_name = $node_parent->name;
            $file_name = $this->findFileName('', $function_name, 'function');
            return "<TYPE>function</TYPE><FILE>{$file_name}</FILE><NAME>{$function_name}</NAME>";
        }

        return "<TYPE>script</TYPE><FILE>{$this->file}</FILE><NAME>global-scope</NAME>";
    }

    private function findFileName($class_name, $method_name, $type) {
        foreach ($this->functions as $file => $method_list) {
            foreach ($method_list as $method) {
                if ($type === 'method') {
                    preg_match_all("/<NAME>(.*)<\/NAME><CLASS>(.*)<\/CLASS>/", $method, $matches, PREG_SET_ORDER, 0);
                    if (count($matches) === 1 && $matches[0][1] === $method_name && $matches[0][2] === $class_name) {
                        return $file;
                    }
                } elseif ($type === 'function') {
                    preg_match_all("/<NAME>(.*)<\/NAME>/", $method, $matches, PREG_SET_ORDER, 0);
                    if (count($matches) === 1 && $matches[0][1] === $method_name) {
                        return $file;
                    }
                }
            }
        }
        return "";
    }

    private function sendRequest($fields) {
        $fields_string = http_build_query($fields);
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "{$this->url}/update-graph");
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $fields_string);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $data = curl_exec($ch);
        if ($data === false) {
            echo "CURL Error: " . curl_error($ch) . "\n";
        }
        curl_close($ch);

        $response = json_decode($data, true);
        if (isset($response["success"]) && $response["success"] === false) {
            echo "Error in request\n";
        }
    }
}

$config = parse_ini_file("./conf.ini", true);
if ($config === false) {
    die("Error reading config file\n");
}

$files_path = $config["DEFAULT"]["php-files"];
$files = file($files_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
if ($files === false) {
    die("Error reading file list\n");
}

$url = "http://{$config['DEFAULT']['host_graph_service']}:{$config['DEFAULT']['host_port_service']}";
$functions = [];
$astMap = [];

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "{$url}/init-graph");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$data = curl_exec($ch);
if ($data === false) {
    die("CURL Error: " . curl_error($ch) . "\n");
}
curl_close($ch);

$parser = (new ParserFactory)->create(ParserFactory::PREFER_PHP7);
$traverser = new NodeTraverser;
$traverser->addVisitor(new ParentConnectingVisitor);

// Parse all files and store their ASTs
foreach ($files as $file) {
    $code = file_get_contents($file);
    if ($code === false) {
        echo "Error reading file {$file}\n";
        continue;
    }

    try {
        $stmts = $parser->parse($code);
        $astMap[$file] = $stmts;
    } catch (Exception $e) {
        echo "Error parsing file {$file}: {$e->getMessage()}\n";
    }
}

// Traverse ASTs to collect function definitions
foreach ($files as $file) {
    try {
        $stmts = $astMap[$file];
        $function_def_visitor = new FunctionDefVisitor($file, $functions);
        $traverser->addVisitor($function_def_visitor);
        $traverser->traverse($stmts);
        $traverser->removeVisitor($function_def_visitor);
        $functions = $function_def_visitor->functions;
    } catch (Exception $e) {
        echo "Error traversing file {$file}: {$e->getMessage()}\n";
    }
}

// Traverse ASTs to build call graph
foreach ($files as $file) {
    try {
        $stmts = $astMap[$file];
        $call_graph_visitor = new CallGraphVisitor($file, $url, $functions, $astMap);
        $traverser->addVisitor($call_graph_visitor);
        $traverser->traverse($stmts);
        $traverser->removeVisitor($call_graph_visitor);
    } catch (Exception $e) {
        echo "Error traversing file {$file}: {$e->getMessage()}\n";
    }
}
?>
