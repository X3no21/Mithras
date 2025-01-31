<?php

require "vendor/autoload.php";

use PhpParser\NodeTraverser;
use PhpParser\ParserFactory;
use PhpParser\NodeVisitorAbstract;
use PhpParser\Node;
use PhpParser\NodeVisitor\ParentConnectingVisitor;

class CustomVisitor extends NodeVisitorAbstract
{
    public $file;
    public $buffer;
    public $out_filename;
    public $target_calls;

    function __construct($file, &$buffer, $out_filename)
    {
        $this->file = $file;
        $this->buffer = &$buffer;
        $this->target_calls = array("pcntl_exec", "shell_exec", "exec", "system", "passthru");
        $this->out_filename = $out_filename;
    }

    public function leaveNode(Node $node)
    {
        if (
            $node instanceof PhpParser\Node\Stmt\Expression
            && $node->expr instanceof PhpParser\Node\Expr\FuncCall
            && $node->expr->name instanceof PhpParser\Node\Name
            && in_array((string)$node->expr->name, $this->target_calls)
        ) {
            $this->find_caller($node);
            return $node;
        }
    }

    public function find_caller(Node $node)
    {
        $node_parent = $node->getAttribute('parent');
        if ($node_parent instanceof PhpParser\Node\Stmt\ClassMethod) {
            $class = $node_parent->getAttribute('parent');
            $str = "$this->file::{$class->name}::{$node_parent->name}\n";
            if (!in_array($str, $this->buffer)) {
                $this->buffer[] = $str;
                file_put_contents($this->out_filename, $str, FILE_APPEND);
            }
        } else if ($node_parent instanceof PhpParser\Node\Stmt\Function_) {
            $str = "$this->file:: ::{$node_parent->name}\n";
            if (!in_array($str, $this->buffer)) {
                $this->buffer[] = $str;
                file_put_contents($this->out_filename, $str, FILE_APPEND);
            }
        } else if ($node_parent != null) {
            $this->find_caller($node_parent);
        }
    }
}

$options = getopt("i:o:");
if (!isset($options['i']) || !isset($options['o'])) {
    die("Usage: php script.php -i input_file -o output_file\n");
}

$input_filename = $options['i'];
$out_filename = $options['o'];

$files = fopen($input_filename, "r");
if ($files === false) {
    die("Failed to open input file: $input_filename\n");
}

file_put_contents($out_filename, '');

$buffer = array();
while (($file = fgets($files)) !== false) {
    $file = trim($file);
    if (file_exists($file)) {
        $code = file_get_contents($file);
        $parser = (new ParserFactory)->create(ParserFactory::PREFER_PHP7);
        $traverser = new NodeTraverser;

        try {
            $stmts = $parser->parse($code);
            $traverser->addVisitor(new ParentConnectingVisitor);
            $traverser->addVisitor(new CustomVisitor($file, $buffer, $out_filename));
            $stmts = $traverser->traverse($stmts);
        } catch (PhpParser\Error $e) {
            echo "Parse error: {$e->getMessage()}\n";
        }
    } else {
        echo "File does not exist: $file\n";
    }
}

fclose($files);
