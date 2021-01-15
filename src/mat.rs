//! Matrices with BN254

use rabe_bn::*;
use rand::prelude::*;

/// Dynamically sized Matrix of a generic value.
#[derive(Eq, PartialEq, Clone, serde::Deserialize, serde::Serialize)]
pub struct Matrix<T> {
    n: usize,
    m: usize,
    inner: Vec<T>,
}

#[allow(dead_code)]
pub type G1Matrix = Matrix<G1>;
#[allow(dead_code)]
pub type G2Matrix = Matrix<G2>;
#[allow(dead_code)]
pub type GtMatrix = Matrix<Gt>;
#[allow(dead_code)]
pub type FrMatrix = Matrix<Fr>;

// XXX: room for optimization for Vectors.
#[allow(dead_code)]
pub type G1Vector = Matrix<G1>;
#[allow(dead_code)]
pub type G2Vector = Matrix<G2>;
#[allow(dead_code)]
pub type GtVector = Matrix<Gt>;
#[allow(dead_code)]
pub type FrVector = Matrix<Fr>;

impl<T> Matrix<T>
where
    rand::distributions::Standard: rand::distributions::Distribution<T>,
{
    pub fn from_random<R: Rng>(rand: &mut R, n: usize, m: usize) -> Self {
        let mut inner = Vec::with_capacity(n * m);

        for _ in 0..(n * m) {
            inner.push(rand.gen());
        }
        Self { n, m, inner }
    }
}

macro_rules! constructors {
    ($obj:ty) => {
        impl Matrix<$obj> {
            pub fn ones(n: usize, m: usize) -> Self {
                Self {
                    n,
                    m,
                    inner: vec![<$obj>::one(); n * m],
                }
            }

            pub fn zeroes(n: usize, m: usize) -> Self {
                Self {
                    n,
                    m,
                    inner: vec![<$obj>::zero(); n * m],
                }
            }
        }
    };
}

constructors!(Fr);
constructors!(G1);
constructors!(G2);

impl Matrix<Gt> {
    pub fn ones(n: usize, m: usize) -> Self {
        Self {
            n,
            m,
            inner: vec![Gt::one(); n * m],
        }
    }
}

impl<T> IntoIterator for Matrix<T> {
    type Item = T;
    type IntoIter = <Vec<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a Matrix<T>
where
    T: 'a,
{
    type Item = &'a T;
    type IntoIter = <&'a [T] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        (&self.inner).into_iter()
    }
}

impl<T> Matrix<T> {
    pub fn dims(&self) -> (usize, usize) {
        (self.n, self.m)
    }

    pub fn transposed(&self) -> Self
    where
        T: Clone,
    {
        let mut inner = Vec::with_capacity(self.n * self.m);
        for j in 0..self.m {
            for i in 0..self.n {
                inner.push(self[(i, j)].clone());
            }
        }
        Self {
            n: self.m,
            m: self.n,
            inner,
        }
    }
}

impl G1Matrix {
    /// Pairs every element of the G1 matrix with the generator G2.
    pub fn pair_with_g2(&self) -> GtMatrix {
        let inner = self
            .inner
            .iter()
            .map(|x| rabe_bn::pairing(x.clone(), G2::one()))
            .collect();
        GtMatrix {
            n: self.n,
            m: self.m,
            inner,
        }
    }
}

impl<T> core::ops::IndexMut<usize> for Matrix<T> {
    fn index_mut(&mut self, idx: usize) -> &mut Self::Output {
        &mut self.inner[idx]
    }
}

impl<T> core::ops::Index<usize> for Matrix<T> {
    type Output = T;

    fn index(&self, idx: usize) -> &Self::Output {
        &self.inner[idx]
    }
}

impl<T> core::ops::IndexMut<(usize, usize)> for Matrix<T> {
    fn index_mut(&mut self, idx: (usize, usize)) -> &mut Self::Output {
        &mut self.inner[idx.0 * self.m + idx.1]
    }
}

impl<T> core::ops::Index<(usize, usize)> for Matrix<T> {
    type Output = T;

    fn index(&self, idx: (usize, usize)) -> &Self::Output {
        &self.inner[idx.0 * self.m + idx.1]
    }
}

macro_rules! mult_matrix {
    ($scalar:ty) => {
        /// Point-wise multiply a matrix with one element
        impl core::ops::Mul<$scalar> for Matrix<$scalar> {
            type Output = Matrix<$scalar>;

            fn mul(self, rhs: $scalar) -> Self::Output {
                // For some reason, rabe_bn expects group * field.
                let inner = self.inner.into_iter().map(|x| rhs * x).collect();
                Self::Output {
                    n: self.n,
                    m: self.m,
                    inner,
                }
            }
        }

        /// Standard matrix multiplication
        impl core::ops::Mul<Matrix<$scalar>> for Matrix<$scalar> {
            type Output = Matrix<$scalar>;

            fn mul(self, rhs: Matrix<$scalar>) -> Self::Output {
                assert_eq!(self.m, rhs.n, "Addition with non-matching dimensions");
                let mut inner = Vec::with_capacity(self.n * rhs.m);

                // XXX should be doable by *move* instead of .clone().
                // ij over target dimensions
                for i in 0..self.n {
                    for j in 0..rhs.m {
                        let mut m_ij = <$scalar>::zero();
                        for k in 0..self.m {
                            // G * a = A, Mul implementation is slightly weird.
                            m_ij = m_ij + rhs[(k, j)].clone() * self[(i, k)].clone();
                        }
                        inner.push(m_ij);
                    }
                }

                Self::Output {
                    n: self.n,
                    m: rhs.m,
                    inner,
                }
            }
        }
    };
    ($scalar:ty, $group:ty) => {
        /// Point-wise multiply a matrix with one element
        impl core::ops::Mul<$group> for Matrix<$scalar> {
            type Output = Matrix<$group>;

            fn mul(self, rhs: $group) -> Self::Output {
                // For some reason, rabe_bn expects group * field.
                let inner = self.inner.into_iter().map(|x| rhs * x).collect();
                Self::Output {
                    n: self.n,
                    m: self.m,
                    inner,
                }
            }
        }

        /// Standard matrix multiplication
        impl core::ops::Mul<Matrix<$scalar>> for Matrix<$group> {
            type Output = Matrix<$group>;

            fn mul(self, rhs: Matrix<$scalar>) -> Self::Output {
                assert_eq!(self.m, rhs.n, "Addition with non-matching dimensions");
                let mut inner = Vec::with_capacity(self.n * rhs.m);

                // XXX should be doable by *move* instead of .clone().
                // ij over target dimensions
                for i in 0..self.n {
                    for j in 0..rhs.m {
                        let mut m_ij = <$group>::zero();
                        for k in 0..self.m {
                            // G * a = A, Mul implementation is slightly weird.
                            m_ij = m_ij + self[(i, k)].clone() * rhs[(k, j)].clone();
                        }
                        inner.push(m_ij);
                    }
                }

                Self::Output {
                    n: self.n,
                    m: rhs.m,
                    inner,
                }
            }
        }

        /// Standard matrix multiplication
        impl core::ops::Mul<Matrix<$group>> for Matrix<$scalar> {
            type Output = Matrix<$group>;

            fn mul(self, rhs: Matrix<$group>) -> Self::Output {
                assert_eq!(self.m, rhs.n, "Addition with non-matching dimensions");
                let mut inner = Vec::with_capacity(self.n * rhs.m);

                // XXX should be doable by *move* instead of .clone().
                // ij over target dimensions
                for i in 0..self.n {
                    for j in 0..rhs.m {
                        let mut m_ij = <$group>::zero();
                        for k in 0..self.m {
                            // G * a = A, Mul implementation is slightly weird.
                            m_ij = m_ij + rhs[(k, j)].clone() * self[(i, k)].clone();
                        }
                        inner.push(m_ij);
                    }
                }

                Self::Output {
                    n: self.n,
                    m: rhs.m,
                    inner,
                }
            }
        }
    };
}

mult_matrix!(Fr, G1);
mult_matrix!(Fr, G2);
mult_matrix!(Fr);

/// Standard matrix multiplication.
///
/// For
/// A \in Gt_{i x k}
/// B \in Fr_{k x j}
///
/// Computes C = A * B
/// C_ij = \Pi_k B_kj ^ A_ki
/// for the multiplicatively-written group Gt.
///
/// Equivalent of CiFEr's `cfe_mat_GT_mul_vec`
impl core::ops::Mul<Matrix<Fr>> for Matrix<Gt> {
    type Output = Matrix<Gt>;

    fn mul(self, rhs: Matrix<Fr>) -> Self::Output {
        assert_eq!(self.m, rhs.n, "Addition with non-matching dimensions");
        let mut inner = Vec::with_capacity(self.n * rhs.m);

        // XXX should be doable by *move* instead of .clone().
        // ij over target dimensions
        for i in 0..self.n {
            for j in 0..rhs.m {
                let mut m_ij = Gt::one();
                for k in 0..self.m {
                    // G * a = A, Mul implementation is slightly weird.
                    m_ij = m_ij * self[(i, k)].clone().pow(rhs[(k, j)].clone());
                }
                inner.push(m_ij);
            }
        }

        Self::Output {
            n: self.n,
            m: rhs.m,
            inner,
        }
    }
}

macro_rules! add_matrix {
    ($el:ty) => {
        /// Point-wise multiply a matrix with one element
        impl core::ops::Add for Matrix<$el> {
            type Output = Self;

            fn add(self, rhs: Self) -> Self {
                assert_eq!(self.n, rhs.n, "Addition with non-matching dimensions");
                assert_eq!(self.m, rhs.m, "Addition with non-matching dimensions");

                let inner = self
                    .inner
                    .into_iter()
                    .zip(rhs.inner.into_iter())
                    .map(|(x, y)| x + y)
                    .collect();
                Self {
                    n: self.n,
                    m: self.m,
                    inner,
                }
            }
        }
    };
}

add_matrix!(G1);
add_matrix!(G2);
add_matrix!(Fr);

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
        let a = FrMatrix::from_random(&mut thread_rng(), 1, 1);
        let b = FrMatrix::from_random(&mut thread_rng(), 1, 1);

        assert_ne!(a, b, "Two random matrices are equal");
    }

    #[test]
    fn simple_matrix_ops() {
        // point-wise scalar matrix X group element
        let mat = FrMatrix::from_random(&mut thread_rng(), 2, 2);
        let _ = mat.clone() * G1::one();
        let _ = mat.clone() * G2::one();

        // (hadamard) addition of two matrices
        let a = FrMatrix::from_random(&mut thread_rng(), 2, 2);
        let b = FrMatrix::from_random(&mut thread_rng(), 2, 2);
        let _ = a + b;

        // Standard mat mul
        let a = FrMatrix::from_random(&mut thread_rng(), 3, 3);
        let b = FrMatrix::from_random(&mut thread_rng(), 3, 2);
        let _ = a * b;
    }

    #[test]
    #[should_panic]
    fn non_matching_dims_add() {
        let a = FrMatrix::from_random(&mut thread_rng(), 2, 1);
        let b = FrMatrix::from_random(&mut thread_rng(), 2, 2);
        let _ = a + b;
    }

    #[test]
    #[should_panic]
    fn non_matching_dims_mul() {
        let a = FrMatrix::from_random(&mut thread_rng(), 2, 2);
        let b = FrMatrix::from_random(&mut thread_rng(), 1, 2);
        let _ = a * b;
    }
}
