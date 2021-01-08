//! Matrices with BN254

use rabe_bn::*;
use rand::prelude::*;

/// Dynamically sized Matrix of a generic value.
#[derive(Eq, PartialEq)]
pub struct Matrix<T> {
    n: usize,
    m: usize,
    inner: Vec<T>,
}

pub type G1Matrix = Matrix<G1>;
pub type G2Matrix = Matrix<G2>;
pub type GtMatrix = Matrix<Gt>;
pub type FPMatrix = Matrix<Fr>;

impl<T> Matrix<T>
where
    rand::distributions::Standard: rand::distributions::Distribution<T>,
{
    pub fn from_random<R: Rng>(rand: &mut R, n: usize, m: usize) -> Self {
        let mut inner = Vec::with_capacity(n * m);

        let distribution = rand::distributions::Standard;

        for _ in 0..(n * m) {
            inner.push(rand.gen());
        }
        Self { n, m, inner }
    }
}

impl<T> core::fmt::Debug for Matrix<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Matrix<{}>{{ {} x {} }}", stringify!(T), self.n, self.m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_random_matrices() {
        let a = FPMatrix::from_random(&mut thread_rng(), 1, 1);
        let b = FPMatrix::from_random(&mut thread_rng(), 1, 1);

        assert_ne!(a, b, "Two random matrices are equal");
    }
}
