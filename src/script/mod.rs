pub mod builtins;

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

use rhai::Engine;

use crate::dns::record::ZoneDefinition;
use crate::error::{Error, Result};

use builtins::{ScriptState, register_builtins};

/// Evaluate a zone definition file and return the collected zone definitions.
pub fn evaluate_file(path: &Path) -> Result<Vec<ZoneDefinition>> {
    let state = Rc::new(RefCell::new(ScriptState::default()));

    // Scope the engine so it drops before we try_unwrap the Rc
    {
        let mut engine = Engine::new();

        engine.set_max_expr_depths(64, 32);
        engine.set_max_operations(100_000);
        engine.set_max_string_size(1_000_000);
        engine.set_max_array_size(10_000);
        engine.set_max_map_size(1_000);

        register_builtins(&mut engine, state.clone());

        let ast = engine.compile_file(path.into()).map_err(|e| Error::Script {
            file: path.display().to_string(),
            message: e.to_string(),
        })?;

        engine
            .run_ast(&ast)
            .map_err(|e| Error::Script {
                file: path.display().to_string(),
                message: e.to_string(),
            })?;
    }

    let state = Rc::try_unwrap(state)
        .map_err(|_| Error::Script {
            file: path.display().to_string(),
            message: "internal error: script state still borrowed after evaluation".to_string(),
        })?
        .into_inner();

    let zones = state.into_zones();
    if zones.is_empty() {
        return Err(Error::Script {
            file: path.display().to_string(),
            message: "no zones defined".to_string(),
        });
    }

    Ok(zones)
}

