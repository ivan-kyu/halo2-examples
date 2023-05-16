use std::{marker::PhantomData, println};
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*};
use super::super::chips::my_mip_chip::{MyMerkleConfig, MyMIPChip};

#[derive(Default)]
#[derive(Debug)]
struct MyMIPCircuit<F> {
    pub leaf: F,
    pub proof: Vec<F>
}

impl<F: FieldExt> Circuit<F> for MyMIPCircuit<F> {
    type Config = MyMerkleConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        MyMIPChip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = MyMIPChip::construct(config);

        let (
            mut prev_leaf, 
            mut prev_proof, 
            mut prev_hashed
        ) = chip.assign_first_row(layouter.namespace(|| "first row"))?;

        for _i in 2..4 {
            let cur_hashed = 
                chip.assign_row(
                    layouter.namespace(|| "next row"),
                    &prev_hashed
                )?;

            prev_hashed = cur_hashed;
        }

        chip.expose_public(layouter.namespace(|| "out"), &prev_hashed, 2)?;

        Ok(())
    }
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use super::MyMIPCircuit;
    use halo2_proofs::{dev::MockProver, pasta::Fp};

    #[test]
    fn mymip_1() {
        let k = 3;

        let leaf = 1u64;
        let proof = vec![1u64, 1u64, 1u64, 1u64, 1u64];
        
        let leaf_fp = Fp::from(leaf);
        let proof_fp: Vec<Fp> = proof
            .iter()
            .map(|x| Fp::from(x.to_owned()))
            .collect();
        let root_fp = Fp::from(4);

        let circuit = MyMIPCircuit {
            leaf: leaf_fp,
            proof: proof_fp
        };

        let public_input = vec![leaf_fp, root_fp];

        let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();

        // public_input[2] += Fp::one();
        // let _prover = MockProver::run(k, &circuit, vec![public_input]).unwrap();
        // uncomment the following line and the assert will fail
        // _prover.assert_satisfied();
    }
}
