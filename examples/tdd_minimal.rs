// Minimal FP + TDD example
// This example includes inline tests so `cargo test --examples` runs them in CI.

fn sum_of_even(values: &[i32]) -> i32 {
    values.iter().copied().filter(|n| n % 2 == 0).sum()
}

fn normalize_whitespace(s: &str) -> String {
    // Functional: iterator pipeline, no mutable accumulation exposed externally
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn main() {
    // Keep runtime side-effects minimal; example output only
    let demo = [1, 2, 3, 4, 5, 6];
    println!("sum_of_even = {}", sum_of_even(&demo));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sum_of_even_basic() {
        let input = [1, 2, 3, 4, 5, 6];
        assert_eq!(sum_of_even(&input), 12);
    }

    #[test]
    fn test_sum_of_even_empty() {
        let input: [i32; 0] = [];
        assert_eq!(sum_of_even(&input), 0);
    }

    #[test]
    fn test_sum_of_even_negatives() {
        let input = [-2, -1, 0, 1, 2];
        assert_eq!(sum_of_even(&input), 0); // -2 + 0 + 2 = 0
    }

    #[test]
    fn test_normalize_whitespace() {
        let s = "  a\t\t b \n c  ";
        assert_eq!(normalize_whitespace(s), "a b c");
    }
}

