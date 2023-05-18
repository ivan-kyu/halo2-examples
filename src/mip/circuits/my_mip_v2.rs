use super::super::chips::my_mip_chip_v2::{MyMIPChipV2, MyMIPConfigV2};
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*};

#[derive(Default)]
struct MyMIPCircuitV2<F> {
    pub start_leaf: Value<F>,
    pub elements: Vec<Value<F>>,
    pub indices: Vec<Value<F>>,
}

impl<F: FieldExt> Circuit<F> for MyMIPCircuitV2<F> {
    type Config = MyMIPConfigV2;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    // configure columns a, b, c, instance
    // pass the config to the Chip
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let instance = meta.instance_column();
        MyMIPChipV2::configure(meta, [col_a, col_b, col_c], instance)
    }

    // instantiate chip
    // load private inputs
    // expose public inputs
    // call chip.merkle_prove to generate the root (digest)
    // expose the root (digest) as public
    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let chip = MyMIPChipV2::construct(config);
        
        let start_leaf_cell = chip.load_private(layouter.namespace(|| "load start_leaf"), self.start_leaf)?;

        chip.expose_public(layouter.namespace(|| "public start_leaf"), &start_leaf_cell, 0)?;

        let digest = chip.merkle_prove(
            layouter.namespace(|| "merkle_prove"),
            &start_leaf_cell,
            &self.elements,
            &self.indices,
        )?;

        chip.expose_public(layouter.namespace(|| "public root"), &digest, 1)?;

        Ok(())
    }
}

mod tests {
    use super::MyMIPCircuitV2;
    use halo2_proofs::{circuit::Value, dev::MockProver, pasta::Fp};

    #[test]
    // #[cfg(feature = "dev-graph")]
    fn test_mymip_v2() {
        let start_leaf = 1;
        let elements = vec![1, 2, 1, 2];
        let indices = vec![0, 0, 0, 0];

        let root: u64 = start_leaf + elements.iter().sum::<u64>();

        let start_leaf_fp = Value::known(Fp::from(start_leaf));
        let elements_fp: Vec<Value<Fp>> = elements
            .iter()
            .map(|x| Value::known(Fp::from(x.to_owned())))
            .collect();
        let indices_fp: Vec<Value<Fp>> = indices
            .iter()
            .map(|x| Value::known(Fp::from(x.to_owned())))
            .collect();



        let circuit = MyMIPCircuitV2 {
            start_leaf: start_leaf_fp,
            elements: elements_fp,
            indices: indices_fp,
        };
        
        let public_input = vec![Fp::from(start_leaf), Fp::from(root)];
        let prover = MockProver::run(10, &circuit, vec![public_input.clone()]).unwrap();
        
        prover.assert_satisfied();
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn plot_mymip_v2() {

        let start_leaf = 1;
        let elements = vec![1, 1, 1, 1];
        let indices = vec![0, 0, 0, 0];

        let root: u64 = start_leaf + elements.iter().sum::<u64>();

        let start_leaf_fp = Value::known(Fp::from(start_leaf));
        let elements_fp: Vec<Value<Fp>> = elements
            .iter()
            .map(|x| Value::known(Fp::from(x.to_owned())))
            .collect();
        let indices_fp: Vec<Value<Fp>> = indices
            .iter()
            .map(|x| Value::known(Fp::from(x.to_owned())))
            .collect();

        let circuit = MyMIPCircuitV2 {
            start_leaf: start_leaf_fp,
            elements: elements_fp,
            indices: indices_fp,
        };


        use plotters::prelude::*;
        let root = BitMapBackend::new("mymip_v2-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("mymip_v2 Layout", ("sans-serif", 60)).unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .render(4, &circuit, &root)
            .unwrap();
    }
}