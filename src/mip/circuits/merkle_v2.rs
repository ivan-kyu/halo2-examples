use super::super::chips::merkle_v2::{MerkleTreeV2Chip, MerkleTreeV2Config};
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*};

#[derive(Default)]
struct MerkleTreeV2Circuit<F> {
    pub leaf: Value<F>,
    pub elements: Vec<Value<F>>,
    pub indices: Vec<Value<F>>,
}

impl<F: FieldExt> Circuit<F> for MerkleTreeV2Circuit<F> {
    type Config = MerkleTreeV2Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let instance = meta.instance_column();
        MerkleTreeV2Chip::configure(meta, [col_a, col_b, col_c], instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {

        let chip = MerkleTreeV2Chip::construct(config);
        
        let leaf_cell = chip.load_private(layouter.namespace(|| "load leaf"), self.leaf)?;

        chip.expose_public(layouter.namespace(|| "public leaf"), &leaf_cell, 0)?;

        let digest = chip.merkle_prove(
            layouter.namespace(|| "merkle_prove"),
            &leaf_cell,
            &self.elements,
            &self.indices,
        )?;

        chip.expose_public(layouter.namespace(|| "public root"), &digest, 1)?;


        
        Ok(())
    }
}

mod tests {
    use super::MerkleTreeV2Circuit;
    use halo2_proofs::{circuit::Value, dev::MockProver, pasta::Fp};

    #[test]
    #[cfg(feature = "dev-graph")]
    fn test_merkle_v2() {
        let leaf = 1u64;
        let elements = vec![1, 1, 1, 1];
        let indices = vec![0, 0, 0, 0];

        let root: u64 = leaf + elements.iter().sum::<u64>();

        let leaf_fp = Value::known(Fp::from(leaf));
        let elements_fp: Vec<Value<Fp>> = elements
            .iter()
            .map(|x| Value::known(Fp::from(x.to_owned())))
            .collect();
        let indices_fp: Vec<Value<Fp>> = indices
            .iter()
            .map(|x| Value::known(Fp::from(x.to_owned())))
            .collect();

        let circuit = MerkleTreeV2Circuit {
            leaf: leaf_fp,
            elements: elements_fp,
            indices: indices_fp,
        };

        let public_input = vec![Fp::from(leaf), Fp::from(root)];
        let prover = MockProver::run(5, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();


        // PLOT
        use plotters::prelude::*;
        let root = BitMapBackend::new("mip-v2-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("MIP v2 Layout", ("sans-serif", 60)).unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .render(4, &circuit, &root)
            .unwrap();
    }
}