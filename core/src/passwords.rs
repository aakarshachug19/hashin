//! Functions that take a character set and password length range, and produces a list of all possible passwords
use crate::errors::GenPasswordsError;
use bitmask_enum::bitmask;
// use itertools::Itertools;

/// From https://stackoverflow.com/a/71420578
// Note(saumi): Initially tried using the itertools crate... But it did not have `permutations_with_replacement` so
// basically copy-pasted this implementation of the required function from stack overflow.
// Consider this as importing a crate that has the `permutations_with_replaacement` functions...
struct PermutationsReplacementIter<I> {
    items: Vec<I>,
    permutation: Vec<usize>,
    group_len: usize,
    finished: bool,
}

impl<I: Copy> PermutationsReplacementIter<I> {
    fn increment_permutation(&mut self) -> bool {
        let mut idx = 0;

        loop {
            if idx >= self.permutation.len() {
                return true;
            }

            self.permutation[idx] += 1;

            if self.permutation[idx] >= self.items.len() {
                self.permutation[idx] = 0;
                idx += 1;
            } else {
                return false;
            }
        }
    }

    fn build_vec(&self) -> Vec<I> {
        let mut vec = Vec::with_capacity(self.group_len);

        for idx in &self.permutation {
            vec.push(self.items[*idx]);
        }

        vec
    }
}

impl<I: Copy> Iterator for PermutationsReplacementIter<I> {
    type Item = Vec<I>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let item = self.build_vec();

        if self.increment_permutation() {
            self.finished = true;
        }

        Some(item)
    }
}

trait ToPermutationsWithReplacement {
    type Iter;
    fn permutations_with_replacement(self, group_len: usize) -> Self::Iter;
}

impl<I: Iterator> ToPermutationsWithReplacement for I {
    type Iter = PermutationsReplacementIter<<I as Iterator>::Item>;

    fn permutations_with_replacement(self, group_len: usize) -> Self::Iter {
        let items = self.collect::<Vec<_>>();
        PermutationsReplacementIter {
            permutation: vec![0; group_len],
            group_len,
            finished: group_len == 0 || items.is_empty(),
            items,
        }
    }
}
// ---

#[bitmask(u8)]
pub enum CharSet {
    /// All lower case alphabets. `a-z`
    LowerAlpha,
    /// All upper case alphabets. `A-Z`
    UpperAlpha,
    /// Numbers from `0-9`
    Numeric,
}

/// Returns a Vec containing all valid characters
fn get_chars_vec(val: CharSet) -> Vec<char> {
    let mut chars = vec![];

    if val.contains(CharSet::LowerAlpha) {
        chars.extend('a'..='z');
    }

    if val.contains(CharSet::UpperAlpha) {
        chars.extend('A'..='Z');
    }

    if val.contains(CharSet::Numeric) {
        chars.extend('0'..='9');
    }

    chars
}

/// This function has been deprecated.
/// Please use the iterator version of this: `PasswordGenerator::new`
#[deprecated]
pub fn get_all_password_combinations(
    min_len: usize,
    max_len: usize,
    char_set: CharSet,
) -> Vec<String> {
    let mut passwords = vec![];
    let chars = get_chars_vec(char_set);
    for i in min_len..=max_len {
        passwords.extend(
            chars
                .clone()
                .into_iter()
                .permutations_with_replacement(i)
                .map(|v| v.iter().collect::<String>()),
        );
    }

    passwords
}

/// Struct Iterator to iterate over all permutations of passwords given length ranges and character set
///
/// Usage:
/// ```Rust
/// let passwords = passwords::PasswordGenerator::new(1, 4, CharSet::LowerAlpha | CharSet::Numeric);
///
/// for password in passwords {
///     println!("Password: {}", password);
/// }
/// `
pub struct PasswordGenerator {
    /// Minimum length of passwords
    min_length: usize,
    /// Maximum length of passwords
    max_length: usize,
    /// Valid characters for passwords
    valid_chars: Vec<char>,
    /// Iterator property to keep track of current length of passwords
    current_length: usize,
    /// Iterator property to keep track of current permutations
    current_permutations_iter: PermutationsReplacementIter<char>,
}

impl PasswordGenerator {
    /// Creates a new PasswordGenerator
    /// Requires:
    /// - min_length: Minimum length for passwords
    /// - max_length: Maximum length for passwords
    /// - char_set: Valid characters for passwords
    pub fn new(
        min_length: usize,
        max_length: usize,
        char_set: CharSet,
    ) -> Result<Self, GenPasswordsError> {
        if min_length == 0 {
            return Err(GenPasswordsError::InvalidMinLengthError(min_length));
        }

        if min_length > max_length {
            return Err(GenPasswordsError::MinGreaterThanMaxError(
                min_length, max_length,
            ));
        }

        let chars = get_chars_vec(char_set);

        Ok(Self {
            min_length,
            max_length,
            valid_chars: chars.clone(),
            current_length: min_length,
            current_permutations_iter: chars.into_iter().permutations_with_replacement(min_length),
        })
    }

    /// Used MATH to calculate how many passwords will be generated! LUL
    ///
    /// *NB:* This method is unreliable if there are more than a `u32` worth
    /// passwords to be generator.
    ///
    /// Also, technically speaking, we can generate more than a `usize` worth
    /// of passwords.
    #[deprecated]
    pub fn len(&self) -> usize {
        let r = self.valid_chars.len();
        let a = r.pow(self.min_length as u32);
        let n = (self.max_length - self.min_length + 1) as u32; // Could possibly lose some bits of info

        a * ((r.pow(n) - 1) / (r - 1))
    }

    /// Returns whether or not this [`PasswordGenerator`] is empty.
    /// This function exists because `len()` exists, but `len()` is not
    /// really safe/normal behavior.
    #[deprecated]
    #[allow(deprecated)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Iterator for PasswordGenerator {
    type Item = String;

    /// Iterator over passwords generated by PasswordGenerator``
    fn next(&mut self) -> Option<Self::Item> {
        if self.current_length > self.max_length {
            return None;
        }

        if let Some(next_item) = self.current_permutations_iter.next() {
            Some(next_item.into_iter().collect())
        } else {
            self.current_length += 1;
            if self.current_length > self.max_length {
                return None;
            }

            self.current_permutations_iter = self
                .valid_chars
                .clone()
                .into_iter()
                .permutations_with_replacement(self.current_length);

            // if let Some(next_item) = self.current_permutations_iter.next() {
            //     Some(next_item.into_iter().collect())
            // } else {
            //     None
            // }
            // clippy noted that the above is just a reimplementation of
            // `Option::map()`
            self.current_permutations_iter
                .next()
                .map(|next_item| next_item.into_iter().collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::errors::GenPasswordsError;
    use crate::passwords::{CharSet, PasswordGenerator};

    #[test]
    #[allow(deprecated)]
    fn test_password_generator_len() {
        let password_gen =
            PasswordGenerator::new(2, 4, CharSet::LowerAlpha | CharSet::Numeric).unwrap();

        let len = password_gen.len();
        let mut counter = 0;
        for _ in password_gen {
            counter += 1;
        }
        assert_eq!(len, counter);
    }

    // TODO fix these tests
    // #[test]
    // fn test_min_length_greater_than_max_length_should_fail() {
    //     let password_gen = PasswordGenerator::new(5, 4, CharSet::LowerAlpha | CharSet::Numeric);
    //     assert_eq!(password_gen.err(), Some(()));
    // }

    // #[test]
    // fn test_min_length_of_0_should_fail() {
    //     let password_gen = PasswordGenerator::new(0, 4, CharSet::LowerAlpha | CharSet::Numeric);
    //     assert_eq!(password_gen.err(), Some(()));
    // }
}
