use rust_tree_sitter::{Language, Parser};

fn main() {
    let source = r#"
int main() {
    return 0;
}

class MyClass {
public:
    void method() {}
    virtual void virtual_method() = 0;
    static int static_method() { return 42; }
};

namespace MyNamespace {
    void namespaced_function() {}
}
        "#;

    let parser = Parser::new(Language::Cpp).unwrap();
    let tree = parser.parse(source, None).unwrap();

    println!("=== C++ Function Detection Debug ===");
    println!("Source code:");
    println!("{}", source);
    println!();

    // Show all top-level nodes
    println!("=== Top-level AST nodes ===");
    for (i, child) in tree.root_node().children().enumerate() {
        println!(
            "{}. {}: {:?}",
            i,
            child.kind(),
            child.text().unwrap_or("ERROR")
        );
    }
    println!();

    // Show function definitions
    println!("=== Function definitions ===");
    let function_defs = tree.find_nodes_by_kind("function_definition");
    println!("Found {} function_definition nodes", function_defs.len());
    for (i, func) in function_defs.iter().enumerate() {
        println!("Function def {}: {:?}", i, func.text().unwrap_or("ERROR"));
    }
    println!();

    // Show declarations
    println!("=== Declarations ===");
    let declarations = tree.find_nodes_by_kind("declaration");
    println!("Found {} declaration nodes", declarations.len());
    for (i, decl) in declarations.iter().enumerate() {
        println!("Declaration {}: {:?}", i, decl.text().unwrap_or("ERROR"));

        // Check if it has function declarator
        let has_func_decl = decl
            .children()
            .any(|child| child.kind() == "function_declarator");
        println!("  -> Has function_declarator: {}", has_func_decl);

        if has_func_decl {
            // Show all children of this declaration
            println!("  -> Children:");
            for (j, child) in decl.children().enumerate() {
                println!(
                    "    {}. {}: {:?}",
                    j,
                    child.kind(),
                    child.text().unwrap_or("ERROR")
                );
            }
        }
    }
    println!();

    // Test the actual find_functions method
    println!("=== Testing find_functions method ===");
    let functions = rust_tree_sitter::languages::cpp::CppSyntax::find_functions(&tree, source);
    println!("Found {} functions via find_functions:", functions.len());
    for (name, start, end) in &functions {
        println!("  - {} at line {}:{}", name, start.row + 1, start.column);
    }
    println!();

    // Check if virtual_method is in the results
    let has_virtual_method = functions
        .iter()
        .any(|(name, _, _)| name == "virtual_method");
    println!("Contains 'virtual_method': {}", has_virtual_method);

    if !has_virtual_method {
        println!("ERROR: virtual_method not found! This is the test failure.");
    }
}
