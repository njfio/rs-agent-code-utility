use rust_tree_sitter::error::Result;
use rust_tree_sitter::languages::{
    javascript::JavaScriptSyntax,
    typescript::TypeScriptSyntax,
    python::PythonSyntax,
    c::CSyntax,
    go::GoSyntax,
    rust::RustSyntax,
};
use rust_tree_sitter::Parser;
use std::fs;
use tempfile::TempDir;

/// Test JavaScript missing features: closures, generators, async/await, destructuring, private fields
#[test]
fn test_javascript_missing_features() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let js_file = temp_dir.path().join("test.js");
    
    let js_code = r#"
// Generator function
function* fibonacci() {
    let a = 0, b = 1;
    while (true) {
        yield a;
        [a, b] = [b, a + b];
    }
}

// Async function
async function fetchData(url) {
    const response = await fetch(url);
    return response.json();
}

// Arrow function (closure)
const multiply = (x, y) => x * y;

// Destructuring
const [first, second, ...rest] = [1, 2, 3, 4, 5];
const {name, age} = {name: "John", age: 30};

// Class with private fields
class Counter {
    #count = 0;
    #secret = "hidden";
    
    increment() {
        this.#count++;
    }
    
    getCount() {
        return this.#count;
    }
}
"#;
    
    fs::write(&js_file, js_code).unwrap();
    
    let parser = Parser::new(rust_tree_sitter::Language::JavaScript).unwrap();
    let tree = parser.parse(js_code, None).unwrap();
    
    // Test generator functions
    let generators = JavaScriptSyntax::find_generators(&tree, js_code);
    assert!(generators.len() >= 1);
    assert!(generators.iter().any(|(name, _, _)| name == "fibonacci"));
    
    // Test async functions
    let async_functions = JavaScriptSyntax::find_async_functions(&tree, js_code);
    assert!(async_functions.len() >= 1);
    assert!(async_functions.iter().any(|(name, _, _)| name == "fetchData"));
    
    // Test closures (arrow functions)
    let closures = JavaScriptSyntax::find_closures(&tree, js_code);
    assert!(closures.len() >= 1);
    
    // Test destructuring patterns
    let destructuring = JavaScriptSyntax::find_destructuring_patterns(&tree, js_code);
    assert!(destructuring.len() >= 2); // Array and object destructuring
    
    // Test classes with private fields
    let private_classes = JavaScriptSyntax::find_classes_with_private_fields(&tree, js_code);
    assert!(private_classes.len() >= 1);
    assert!(private_classes.iter().any(|(name, fields, _, _)| {
        name == "Counter" && fields.contains(&"#count".to_string())
    }));
    
    Ok(())
}

/// Test TypeScript missing features: generics, namespaces, mapped types, decorators
#[test]
fn test_typescript_missing_features() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let ts_file = temp_dir.path().join("test.ts");
    
    let ts_code = r#"
// Generic interface
interface Repository<T> {
    save(entity: T): Promise<T>;
    findById(id: string): Promise<T | null>;
}

// Generic type alias
type ApiResponse<T> = {
    data: T;
    status: number;
    message: string;
};

// Namespace
namespace Utils {
    export function formatDate(date: Date): string {
        return date.toISOString();
    }
}

// Mapped type
type Readonly<T> = {
    readonly [P in keyof T]: T[P];
};

// Conditional type
type NonNullable<T> = T extends null | undefined ? never : T;

// Decorator
@Component({
    selector: 'app-user',
    template: '<div>User</div>'
})
class UserComponent {
    @Input() name: string;
    
    @Output() userClick = new EventEmitter();
}
"#;
    
    fs::write(&ts_file, ts_code).unwrap();
    
    let parser = Parser::new(rust_tree_sitter::Language::TypeScript).unwrap();
    let tree = parser.parse(ts_code, None).unwrap();
    
    // Test generic types
    let generic_types = TypeScriptSyntax::find_generic_types(&tree, ts_code);
    assert!(generic_types.len() >= 2); // Repository and ApiResponse
    
    // Test namespaces
    let namespaces = TypeScriptSyntax::find_namespaces(&tree, ts_code);
    assert!(namespaces.len() >= 1);
    assert!(namespaces.iter().any(|(name, _, _)| name == "Utils"));
    
    // Test mapped types
    let mapped_types = TypeScriptSyntax::find_mapped_types(&tree, ts_code);
    assert!(mapped_types.len() >= 1);
    
    // Test conditional types
    let conditional_types = TypeScriptSyntax::find_conditional_types(&tree, ts_code);
    assert!(conditional_types.len() >= 1);
    
    // Test decorators
    let decorators = TypeScriptSyntax::find_decorators(&tree, ts_code);
    assert!(decorators.len() >= 3); // @Component, @Input, @Output
    
    Ok(())
}

/// Test Python missing features: async functions, context managers, metaclasses, dataclasses, type hints
#[test]
fn test_python_missing_features() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let py_file = temp_dir.path().join("test.py");
    
    let py_code = r#"
import asyncio
from dataclasses import dataclass
from typing import List, Optional, Protocol
from contextlib import contextmanager

# Async function
async def fetch_data(url: str) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            return await response.json()

# Context manager
@contextmanager
def database_transaction():
    conn = get_connection()
    trans = conn.begin()
    try:
        yield conn
        trans.commit()
    except:
        trans.rollback()
        raise
    finally:
        conn.close()

# Metaclass
class SingletonMeta(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]

class Singleton(metaclass=SingletonMeta):
    pass

# Dataclass
@dataclass
class User:
    name: str
    age: int
    email: Optional[str] = None

# Typed function with complex types
def process_users(users: List[User]) -> dict[str, int]:
    return {user.name: user.age for user in users}

# Property decorators
class Circle:
    def __init__(self, radius: float):
        self._radius = radius
    
    @property
    def radius(self) -> float:
        return self._radius
    
    @staticmethod
    def from_diameter(diameter: float) -> 'Circle':
        return Circle(diameter / 2)
    
    @classmethod
    def unit_circle(cls) -> 'Circle':
        return cls(1.0)

# Lambda functions
square = lambda x: x ** 2
filter_even = lambda lst: [x for x in lst if x % 2 == 0]
"#;
    
    fs::write(&py_file, py_code).unwrap();
    
    let parser = Parser::new(rust_tree_sitter::Language::Python).unwrap();
    let tree = parser.parse(py_code, None).unwrap();
    
    // Test async functions
    let async_functions = PythonSyntax::find_async_functions(&tree, py_code);
    assert!(async_functions.len() >= 1);
    assert!(async_functions.iter().any(|(name, _, _)| name == "fetch_data"));
    
    // Test context managers
    let context_managers = PythonSyntax::find_context_managers(&tree, py_code);
    assert!(context_managers.len() >= 1);
    
    // Test metaclasses
    let metaclasses = PythonSyntax::find_metaclasses(&tree, py_code);
    assert!(metaclasses.len() >= 1);
    assert!(metaclasses.iter().any(|(class_name, meta_name, _, _)| {
        class_name == "Singleton" && meta_name == "SingletonMeta"
    }));
    
    // Test dataclasses
    let dataclasses = PythonSyntax::find_dataclasses(&tree, py_code);
    assert!(dataclasses.len() >= 1);
    assert!(dataclasses.iter().any(|(name, _, _)| name == "User"));
    
    // Test typed functions
    let typed_functions = PythonSyntax::find_typed_functions(&tree, py_code);
    assert!(typed_functions.len() >= 2); // fetch_data and process_users
    
    // Test property decorators
    let property_decorators = PythonSyntax::find_property_decorators(&tree, py_code);
    assert!(property_decorators.len() >= 3); // @property, @staticmethod, @classmethod
    
    // Test lambda functions
    let lambdas = PythonSyntax::find_lambda_functions(&tree, py_code);
    assert!(lambdas.len() >= 2); // square and filter_even
    
    Ok(())
}

/// Test C missing features: function pointers, unions, bit fields, preprocessor macros, static functions
#[test]
fn test_c_missing_features() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let c_file = temp_dir.path().join("test.c");
    
    let c_code = r#"
#include <stdio.h>

// Preprocessor macros
#define MAX_SIZE 100
#define SQUARE(x) ((x) * (x))
#define DEBUG_PRINT(fmt, ...) printf("[DEBUG] " fmt "\n", ##__VA_ARGS__)

// Function pointer declaration
typedef int (*operation_t)(int, int);

// Union declaration
union Data {
    int integer;
    float floating;
    char string[20];
};

// Struct with bit fields
struct Flags {
    unsigned int flag1 : 1;
    unsigned int flag2 : 1;
    unsigned int reserved : 6;
    unsigned int value : 24;
};

// Static function
static int internal_helper(int x) {
    return x * 2;
}

// Inline function
inline int fast_add(int a, int b) {
    return a + b;
}

// Function using function pointer
int calculate(int a, int b, operation_t op) {
    return op(a, b);
}

// Function implementations for function pointers
int add(int a, int b) { return a + b; }
int multiply(int a, int b) { return a * b; }
"#;
    
    fs::write(&c_file, c_code).unwrap();
    
    let parser = Parser::new(rust_tree_sitter::Language::C).unwrap();
    let tree = parser.parse(c_code, None).unwrap();
    
    // Test function pointers
    let function_pointers = CSyntax::find_function_pointers(&tree, c_code);
    assert!(function_pointers.len() >= 1);
    assert!(function_pointers.iter().any(|(name, _, _, _)| name == "operation_t"));
    
    // Test unions
    let unions = CSyntax::find_unions(&tree, c_code);
    assert!(unions.len() >= 1);
    assert!(unions.iter().any(|(name, _, _)| name == "Data"));
    
    // Test bit fields
    let bit_fields = CSyntax::find_bit_fields(&tree, c_code);
    assert!(bit_fields.len() >= 4); // flag1, flag2, reserved, value
    
    // Test preprocessor macros
    let macros = CSyntax::find_preprocessor_macros(&tree, c_code);
    assert!(macros.len() >= 3); // MAX_SIZE, SQUARE, DEBUG_PRINT
    
    // Test static functions
    let static_functions = CSyntax::find_static_functions(&tree, c_code);
    assert!(static_functions.len() >= 1);
    assert!(static_functions.iter().any(|(name, _, _)| name == "internal_helper"));
    
    // Test inline functions
    let inline_functions = CSyntax::find_inline_functions(&tree, c_code);
    assert!(inline_functions.len() >= 1);
    assert!(inline_functions.iter().any(|(name, _, _)| name == "fast_add"));
    
    Ok(())
}

/// Test Go missing features: interfaces, channels, goroutines, embedded types, type assertions
#[test]
fn test_go_missing_features() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let go_file = temp_dir.path().join("test.go");

    let go_code = r#"
package main

import (
    "fmt"
    "time"
)

// Interface definition
type Writer interface {
    Write([]byte) (int, error)
    Close() error
}

type Reader interface {
    Read([]byte) (int, error)
}

// Embedded types in struct
type Person struct {
    Name string
    Age  int
}

type Employee struct {
    Person  // Embedded type
    ID      int
    Salary  float64
}

// Channel operations and goroutines
func processData() {
    // Channel creation
    ch := make(chan int, 10)
    done := make(chan bool)

    // Goroutine launch
    go func() {
        for i := 0; i < 5; i++ {
            ch <- i
            time.Sleep(100 * time.Millisecond)
        }
        close(ch)
        done <- true
    }()

    // Select statement for channel operations
    go func() {
        for {
            select {
            case value := <-ch:
                fmt.Println("Received:", value)
            case <-done:
                return
            default:
                fmt.Println("No data available")
                time.Sleep(50 * time.Millisecond)
            }
        }
    }()

    // Type assertion
    var x interface{} = "hello world"
    if str, ok := x.(string); ok {
        fmt.Println("String value:", str)
    }

    // Defer statement
    defer fmt.Println("Function completed")
}

func main() {
    processData()
    time.Sleep(1 * time.Second)
}
"#;

    fs::write(&go_file, go_code).unwrap();

    let parser = Parser::new(rust_tree_sitter::Language::Go).unwrap();
    let tree = parser.parse(go_code, None).unwrap();

    // Test interfaces
    let interfaces = GoSyntax::find_interfaces(&tree, go_code);
    assert!(interfaces.len() >= 2); // Writer and Reader
    assert!(interfaces.iter().any(|(name, methods, _, _)| {
        name == "Writer" && methods.contains(&"Write".to_string())
    }));

    // Test channels
    let channels = GoSyntax::find_channels(&tree, go_code);
    assert!(channels.len() >= 2); // ch and done channels

    // Test goroutines
    let goroutines = GoSyntax::find_goroutines(&tree, go_code);
    assert!(goroutines.len() >= 2); // Two go statements

    // Test embedded types
    let embedded_types = GoSyntax::find_embedded_types(&tree, go_code);
    assert!(embedded_types.len() >= 1);
    assert!(embedded_types.iter().any(|(struct_name, embedded, _, _)| {
        struct_name == "Employee" && embedded.contains(&"Person".to_string())
    }));

    // Test type assertions
    let type_assertions = GoSyntax::find_type_assertions(&tree, go_code);
    assert!(type_assertions.len() >= 1);

    Ok(())
}

/// Test Rust missing features: traits, impl blocks, macros, lifetimes, associated types, const generics
#[test]
fn test_rust_missing_features() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let rust_file = temp_dir.path().join("test.rs");

    let rust_code = r#"
use std::fmt::Display;

// Trait definition with associated types
trait Iterator {
    type Item;

    fn next(&mut self) -> Option<Self::Item>;
    fn size_hint(&self) -> (usize, Option<usize>);
}

// Trait with lifetime parameters
trait Borrowable<'a> {
    type Borrowed: 'a;

    fn borrow(&'a self) -> Self::Borrowed;
}

// Struct with const generics
struct Array<T, const N: usize> {
    data: [T; N],
}

// Impl block for struct
impl<T, const N: usize> Array<T, N> {
    fn new(data: [T; N]) -> Self {
        Self { data }
    }

    fn len(&self) -> usize {
        N
    }
}

// Trait implementation
impl<T: Display, const N: usize> Display for Array<T, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Array[{}]", N)
    }
}

// Macro definition
macro_rules! vec_of {
    ($elem:expr; $n:expr) => {
        std::vec::from_elem($elem, $n)
    };
    ($($x:expr),+ $(,)?) => {
        <[_]>::into_vec(Box::new([$($x),+]))
    };
}

// Function with lifetime parameters
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() {
        x
    } else {
        y
    }
}

// Generic function with where clause
fn compare_and_display<T>(t: &T, u: &T) -> bool
where
    T: Display + PartialEq,
{
    println!("Comparing {} and {}", t, u);
    t == u
}
"#;

    fs::write(&rust_file, rust_code).unwrap();

    let parser = Parser::new(rust_tree_sitter::Language::Rust).unwrap();
    let tree = parser.parse(rust_code, None).unwrap();

    // Test traits
    let traits = RustSyntax::find_traits(&tree, rust_code);
    assert!(traits.len() >= 2); // Iterator and Borrowable
    assert!(traits.iter().any(|(name, methods, _, _)| {
        name == "Iterator" && methods.contains(&"next".to_string())
    }));

    // Test impl blocks
    let impl_blocks = RustSyntax::find_impl_blocks(&tree, rust_code);
    assert!(impl_blocks.len() >= 2); // impl for Array and Display impl
    assert!(impl_blocks.iter().any(|(type_name, trait_name, _, _, _)| {
        type_name == "Array" && trait_name.is_none() // inherent impl
    }));
    assert!(impl_blocks.iter().any(|(type_name, trait_name, _, _, _)| {
        type_name == "Array" && trait_name.as_ref().map(|t| t.contains("Display")).unwrap_or(false)
    }));

    // Test macros
    let macros = RustSyntax::find_macros(&tree, rust_code);
    assert!(macros.len() >= 1);
    assert!(macros.iter().any(|(name, _, _, _)| name == "vec_of"));

    // Test lifetimes
    let lifetimes = RustSyntax::find_lifetimes(&tree, rust_code);
    assert!(lifetimes.len() >= 1);
    assert!(lifetimes.iter().any(|(func_name, lifetime, _, _)| {
        func_name == "longest" && lifetime.contains("'a")
    }));

    // Test associated types
    let associated_types = RustSyntax::find_associated_types(&tree, rust_code);
    assert!(associated_types.len() >= 2); // Item and Borrowed
    assert!(associated_types.iter().any(|(trait_name, type_name, _, _)| {
        trait_name == "Iterator" && type_name == "Item"
    }));

    // Test const generics
    let const_generics = RustSyntax::find_const_generics(&tree, rust_code);
    assert!(const_generics.len() >= 1);
    assert!(const_generics.iter().any(|(struct_name, const_param, _, _)| {
        struct_name == "Array" && const_param.contains("N: usize")
    }));

    Ok(())
}
