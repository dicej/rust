//! Generates `assists.md` documentation.

use std::{fmt, fs, path::PathBuf};

use crate::{
    codegen::{self, extract_comment_blocks_with_empty_lines, Mode},
    project_root, rust_files, Result,
};

pub fn generate_feature_docs(mode: Mode) -> Result<()> {
    let features = Feature::collect()?;
    let contents = features.into_iter().map(|it| it.to_string()).collect::<Vec<_>>().join("\n\n");

    let dst = project_root().join("docs/user/generated_features.adoc");
    codegen::update(&dst, &contents, mode)?;
    Ok(())
}

#[derive(Debug)]
struct Feature {
    id: String,
    path: PathBuf,
    doc: String,
}

impl Feature {
    fn collect() -> Result<Vec<Feature>> {
        let mut res = Vec::new();
        for path in rust_files(&project_root()) {
            collect_file(&mut res, path)?;
        }
        res.sort_by(|lhs, rhs| lhs.id.cmp(&rhs.id));
        return Ok(res);

        fn collect_file(acc: &mut Vec<Feature>, path: PathBuf) -> Result<()> {
            let text = fs::read_to_string(&path)?;
            let comment_blocks = extract_comment_blocks_with_empty_lines("Feature", &text);

            for block in comment_blocks {
                let id = block.id;
                assert!(
                    id.split_ascii_whitespace().all(|it| it.starts_with(char::is_uppercase)),
                    "bad feature: {}",
                    id
                );
                let doc = block.contents.join("\n");
                acc.push(Feature { id, path: path.clone(), doc })
            }

            Ok(())
        }
    }
}

impl fmt::Display for Feature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== {}", self.id)?;
        let path = self.path.strip_prefix(&project_root()).unwrap();
        let name = self.path.file_name().unwrap();

        //FIXME: generate line number as well
        writeln!(
            f,
            "**Source:** https://github.com/rust-analyzer/rust-analyzer/blob/master/{}[{}]",
            path.display(),
            name.to_str().unwrap(),
        )?;

        writeln!(f, "\n{}", self.doc)?;
        Ok(())
    }
}
