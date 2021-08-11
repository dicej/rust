//! This module contains functions to generate default trait impl function bodies where possible.

use syntax::{
    ast::{self, edit::AstNodeEdit, make, AstNode, NameOwner},
    ted,
};

/// Generate custom trait bodies where possible.
///
/// Returns `Option` so that we can use `?` rather than `if let Some`. Returning
/// `None` means that generating a custom trait body failed, and the body will remain
/// as `todo!` instead.
pub(crate) fn gen_trait_fn_body(
    func: &ast::Fn,
    trait_path: &ast::Path,
    adt: &ast::Adt,
) -> Option<()> {
    match trait_path.segment()?.name_ref()?.text().as_str() {
        "Clone" => gen_clone_impl(adt, func),
        "Debug" => gen_debug_impl(adt, func),
        "Default" => gen_default_impl(adt, func),
        "Hash" => gen_hash_impl(adt, func),
        "PartialEq" => gen_partial_eq(adt, func),
        _ => None,
    }
}

/// Generate a `Clone` impl based on the fields and members of the target type.
fn gen_clone_impl(adt: &ast::Adt, func: &ast::Fn) -> Option<()> {
    fn gen_clone_call(target: ast::Expr) -> ast::Expr {
        let method = make::name_ref("clone");
        make::expr_method_call(target, method, make::arg_list(None))
    }
    let expr = match adt {
        // `Clone` cannot be derived for unions, so no default impl can be provided.
        ast::Adt::Union(_) => return None,
        ast::Adt::Enum(enum_) => {
            let list = enum_.variant_list()?;
            let mut arms = vec![];
            for variant in list.variants() {
                let name = variant.name()?;
                let left = make::ext::ident_path("Self");
                let right = make::ext::ident_path(&format!("{}", name));
                let variant_name = make::path_concat(left, right);

                match variant.field_list() {
                    // => match self { Self::Name { x } => Self::Name { x: x.clone() } }
                    Some(ast::FieldList::RecordFieldList(list)) => {
                        let mut pats = vec![];
                        let mut fields = vec![];
                        for field in list.fields() {
                            let field_name = field.name()?;
                            let pat = make::ident_pat(false, false, field_name.clone());
                            pats.push(pat.into());

                            let path = make::ext::ident_path(&field_name.to_string());
                            let method_call = gen_clone_call(make::expr_path(path));
                            let name_ref = make::name_ref(&field_name.to_string());
                            let field = make::record_expr_field(name_ref, Some(method_call));
                            fields.push(field);
                        }
                        let pat = make::record_pat(variant_name.clone(), pats.into_iter());
                        let fields = make::record_expr_field_list(fields);
                        let record_expr = make::record_expr(variant_name, fields).into();
                        arms.push(make::match_arm(Some(pat.into()), None, record_expr));
                    }

                    // => match self { Self::Name(arg1) => Self::Name(arg1.clone()) }
                    Some(ast::FieldList::TupleFieldList(list)) => {
                        let mut pats = vec![];
                        let mut fields = vec![];
                        for (i, _) in list.fields().enumerate() {
                            let field_name = format!("arg{}", i);
                            let pat = make::ident_pat(false, false, make::name(&field_name));
                            pats.push(pat.into());

                            let f_path = make::expr_path(make::ext::ident_path(&field_name));
                            fields.push(gen_clone_call(f_path));
                        }
                        let pat = make::tuple_struct_pat(variant_name.clone(), pats.into_iter());
                        let struct_name = make::expr_path(variant_name);
                        let tuple_expr = make::expr_call(struct_name, make::arg_list(fields));
                        arms.push(make::match_arm(Some(pat.into()), None, tuple_expr));
                    }

                    // => match self { Self::Name => Self::Name }
                    None => {
                        let pattern = make::path_pat(variant_name.clone());
                        let variant_expr = make::expr_path(variant_name);
                        arms.push(make::match_arm(Some(pattern.into()), None, variant_expr));
                    }
                }
            }

            let match_target = make::expr_path(make::ext::ident_path("self"));
            let list = make::match_arm_list(arms).indent(ast::edit::IndentLevel(1));
            make::expr_match(match_target, list)
        }
        ast::Adt::Struct(strukt) => {
            match strukt.field_list() {
                // => Self { name: self.name.clone() }
                Some(ast::FieldList::RecordFieldList(field_list)) => {
                    let mut fields = vec![];
                    for field in field_list.fields() {
                        let base = make::expr_path(make::ext::ident_path("self"));
                        let target = make::expr_field(base, &field.name()?.to_string());
                        let method_call = gen_clone_call(target);
                        let name_ref = make::name_ref(&field.name()?.to_string());
                        let field = make::record_expr_field(name_ref, Some(method_call));
                        fields.push(field);
                    }
                    let struct_name = make::ext::ident_path("Self");
                    let fields = make::record_expr_field_list(fields);
                    make::record_expr(struct_name, fields).into()
                }
                // => Self(self.0.clone(), self.1.clone())
                Some(ast::FieldList::TupleFieldList(field_list)) => {
                    let mut fields = vec![];
                    for (i, _) in field_list.fields().enumerate() {
                        let f_path = make::expr_path(make::ext::ident_path("self"));
                        let target = make::expr_field(f_path, &format!("{}", i)).into();
                        fields.push(gen_clone_call(target));
                    }
                    let struct_name = make::expr_path(make::ext::ident_path("Self"));
                    make::expr_call(struct_name, make::arg_list(fields))
                }
                // => Self { }
                None => {
                    let struct_name = make::ext::ident_path("Self");
                    let fields = make::record_expr_field_list(None);
                    make::record_expr(struct_name, fields).into()
                }
            }
        }
    };
    let body = make::block_expr(None, Some(expr)).indent(ast::edit::IndentLevel(1));
    ted::replace(func.body()?.syntax(), body.clone_for_update().syntax());
    Some(())
}

/// Generate a `Debug` impl based on the fields and members of the target type.
fn gen_debug_impl(adt: &ast::Adt, func: &ast::Fn) -> Option<()> {
    let annotated_name = adt.name()?;
    match adt {
        // `Debug` cannot be derived for unions, so no default impl can be provided.
        ast::Adt::Union(_) => None,

        // => match self { Self::Variant => write!(f, "Variant") }
        ast::Adt::Enum(enum_) => {
            let list = enum_.variant_list()?;
            let mut arms = vec![];
            for variant in list.variants() {
                let name = variant.name()?;
                let left = make::ext::ident_path("Self");
                let right = make::ext::ident_path(&format!("{}", name));
                let variant_name = make::path_pat(make::path_concat(left, right));

                let target = make::expr_path(make::ext::ident_path("f").into());
                let fmt_string = make::expr_literal(&(format!("\"{}\"", name))).into();
                let args = make::arg_list(vec![target, fmt_string]);
                let macro_name = make::expr_path(make::ext::ident_path("write"));
                let macro_call = make::expr_macro_call(macro_name, args);

                arms.push(make::match_arm(Some(variant_name.into()), None, macro_call.into()));
            }

            let match_target = make::expr_path(make::ext::ident_path("self"));
            let list = make::match_arm_list(arms).indent(ast::edit::IndentLevel(1));
            let match_expr = make::expr_match(match_target, list);

            let body = make::block_expr(None, Some(match_expr));
            let body = body.indent(ast::edit::IndentLevel(1));
            ted::replace(func.body()?.syntax(), body.clone_for_update().syntax());
            Some(())
        }

        ast::Adt::Struct(strukt) => {
            let name = format!("\"{}\"", annotated_name);
            let args = make::arg_list(Some(make::expr_literal(&name).into()));
            let target = make::expr_path(make::ext::ident_path("f"));

            let expr = match strukt.field_list() {
                // => f.debug_struct("Name").finish()
                None => make::expr_method_call(target, make::name_ref("debug_struct"), args),

                // => f.debug_struct("Name").field("foo", &self.foo).finish()
                Some(ast::FieldList::RecordFieldList(field_list)) => {
                    let method = make::name_ref("debug_struct");
                    let mut expr = make::expr_method_call(target, method, args);
                    for field in field_list.fields() {
                        let name = field.name()?;
                        let f_name = make::expr_literal(&(format!("\"{}\"", name))).into();
                        let f_path = make::expr_path(make::ext::ident_path("self"));
                        let f_path = make::expr_ref(f_path, false);
                        let f_path = make::expr_field(f_path, &format!("{}", name)).into();
                        let args = make::arg_list(vec![f_name, f_path]);
                        expr = make::expr_method_call(expr, make::name_ref("field"), args);
                    }
                    expr
                }

                // => f.debug_tuple("Name").field(self.0).finish()
                Some(ast::FieldList::TupleFieldList(field_list)) => {
                    let method = make::name_ref("debug_tuple");
                    let mut expr = make::expr_method_call(target, method, args);
                    for (i, _) in field_list.fields().enumerate() {
                        let f_path = make::expr_path(make::ext::ident_path("self"));
                        let f_path = make::expr_ref(f_path, false);
                        let f_path = make::expr_field(f_path, &format!("{}", i)).into();
                        let method = make::name_ref("field");
                        expr = make::expr_method_call(expr, method, make::arg_list(Some(f_path)));
                    }
                    expr
                }
            };

            let method = make::name_ref("finish");
            let expr = make::expr_method_call(expr, method, make::arg_list(None));
            let body = make::block_expr(None, Some(expr)).indent(ast::edit::IndentLevel(1));
            ted::replace(func.body()?.syntax(), body.clone_for_update().syntax());
            Some(())
        }
    }
}

/// Generate a `Debug` impl based on the fields and members of the target type.
fn gen_default_impl(adt: &ast::Adt, func: &ast::Fn) -> Option<()> {
    fn gen_default_call() -> ast::Expr {
        let trait_name = make::ext::ident_path("Default");
        let method_name = make::ext::ident_path("default");
        let fn_name = make::expr_path(make::path_concat(trait_name, method_name));
        make::expr_call(fn_name, make::arg_list(None))
    }
    match adt {
        // `Debug` cannot be derived for unions, so no default impl can be provided.
        ast::Adt::Union(_) => None,
        // Deriving `Debug` for enums is not stable yet.
        ast::Adt::Enum(_) => None,
        ast::Adt::Struct(strukt) => {
            let expr = match strukt.field_list() {
                Some(ast::FieldList::RecordFieldList(field_list)) => {
                    let mut fields = vec![];
                    for field in field_list.fields() {
                        let method_call = gen_default_call();
                        let name_ref = make::name_ref(&field.name()?.to_string());
                        let field = make::record_expr_field(name_ref, Some(method_call));
                        fields.push(field);
                    }
                    let struct_name = make::ext::ident_path("Self");
                    let fields = make::record_expr_field_list(fields);
                    make::record_expr(struct_name, fields).into()
                }
                Some(ast::FieldList::TupleFieldList(field_list)) => {
                    let struct_name = make::expr_path(make::ext::ident_path("Self"));
                    let fields = field_list.fields().map(|_| gen_default_call());
                    make::expr_call(struct_name, make::arg_list(fields))
                }
                None => {
                    let struct_name = make::ext::ident_path("Self");
                    let fields = make::record_expr_field_list(None);
                    make::record_expr(struct_name, fields).into()
                }
            };
            let body = make::block_expr(None, Some(expr)).indent(ast::edit::IndentLevel(1));
            ted::replace(func.body()?.syntax(), body.clone_for_update().syntax());
            Some(())
        }
    }
}

/// Generate a `Hash` impl based on the fields and members of the target type.
fn gen_hash_impl(adt: &ast::Adt, func: &ast::Fn) -> Option<()> {
    fn gen_hash_call(target: ast::Expr) -> ast::Stmt {
        let method = make::name_ref("hash");
        let arg = make::expr_path(make::ext::ident_path("state"));
        let expr = make::expr_method_call(target, method, make::arg_list(Some(arg)));
        let stmt = make::expr_stmt(expr);
        stmt.into()
    }

    let body = match adt {
        // `Hash` cannot be derived for unions, so no default impl can be provided.
        ast::Adt::Union(_) => return None,

        // => std::mem::discriminant(self).hash(state);
        ast::Adt::Enum(_) => {
            let root = make::ext::ident_path("core");
            let submodule = make::ext::ident_path("mem");
            let fn_name = make::ext::ident_path("discriminant");
            let fn_name = make::path_concat(submodule, fn_name);
            let fn_name = make::expr_path(make::path_concat(root, fn_name));

            let arg = make::expr_path(make::ext::ident_path("self"));
            let fn_call = make::expr_call(fn_name, make::arg_list(Some(arg)));
            let stmt = gen_hash_call(fn_call);

            make::block_expr(Some(stmt), None).indent(ast::edit::IndentLevel(1))
        }
        ast::Adt::Struct(strukt) => match strukt.field_list() {
            // => self.<field>.hash(state);
            Some(ast::FieldList::RecordFieldList(field_list)) => {
                let mut stmts = vec![];
                for field in field_list.fields() {
                    let base = make::expr_path(make::ext::ident_path("self"));
                    let target = make::expr_field(base, &field.name()?.to_string());
                    stmts.push(gen_hash_call(target));
                }
                make::block_expr(stmts, None).indent(ast::edit::IndentLevel(1))
            }

            // => self.<field_index>.hash(state);
            Some(ast::FieldList::TupleFieldList(field_list)) => {
                let mut stmts = vec![];
                for (i, _) in field_list.fields().enumerate() {
                    let base = make::expr_path(make::ext::ident_path("self"));
                    let target = make::expr_field(base, &format!("{}", i));
                    stmts.push(gen_hash_call(target));
                }
                make::block_expr(stmts, None).indent(ast::edit::IndentLevel(1))
            }

            // No fields in the body means there's nothing to hash.
            None => return None,
        },
    };

    ted::replace(func.body()?.syntax(), body.clone_for_update().syntax());
    Some(())
}

/// Generate a `PartialEq` impl based on the fields and members of the target type.
fn gen_partial_eq(adt: &ast::Adt, func: &ast::Fn) -> Option<()> {
    fn gen_discriminant() -> ast::Expr {
        let root = make::ext::ident_path("core");
        let submodule = make::ext::ident_path("mem");
        let fn_name = make::ext::ident_path("discriminant");
        let fn_name = make::path_concat(submodule, fn_name);
        let fn_name = make::expr_path(make::path_concat(root, fn_name));
        fn_name
    }

    // FIXME: return `None` if the trait carries a generic type; we can only
    // generate this code `Self` for the time being.

    let body = match adt {
        // `Hash` cannot be derived for unions, so no default impl can be provided.
        ast::Adt::Union(_) => return None,

        ast::Adt::Enum(enum_) => {
            // => std::mem::discriminant(self) == std::mem::discriminant(other)
            let self_name = make::expr_path(make::ext::ident_path("self"));
            let lhs = make::expr_call(gen_discriminant(), make::arg_list(Some(self_name.clone())));
            let other_name = make::expr_path(make::ext::ident_path("other"));
            let rhs = make::expr_call(gen_discriminant(), make::arg_list(Some(other_name.clone())));
            let eq_check = make::expr_op(ast::BinOp::EqualityTest, lhs, rhs);

            let mut case_count = 0;
            let mut arms = vec![];
            for variant in enum_.variant_list()?.variants() {
                case_count += 1;
                match variant.field_list() {
                    // => (Self::Bar { bin: l_bin }, Self::Bar { bin: r_bin }) => l_bin == r_bin,
                    Some(ast::FieldList::RecordFieldList(list)) => {
                        let mut expr = None;
                        let mut l_fields = vec![];
                        let mut r_fields = vec![];
                        // let mut fields = vec![];

                        // !! make::record_pat_field{list, etc};

                        for field in list.fields() {
                            let field_name = field.name()?.to_string();

                            let l_name = &format!("l_{}", field_name);
                            let pat = make::ext::simple_ident_pat(make::name(&l_name));
                            let name_ref = make::name_ref(&field_name);
                            let field = make::record_pat_field(name_ref, pat.into());
                            l_fields.push(field);

                            let r_name = &format!("r_{}", field_name);
                            let pat = make::ext::simple_ident_pat(make::name(&r_name));
                            let name_ref = make::name_ref(&field_name);
                            let field = make::record_pat_field(name_ref, pat.into());
                            r_fields.push(field);

                            let lhs = make::expr_path(make::ext::ident_path(l_name));
                            let rhs = make::expr_path(make::ext::ident_path(r_name));
                            let cmp = make::expr_op(ast::BinOp::EqualityTest, lhs, rhs);
                            expr = match expr {
                                Some(expr) => {
                                    Some(make::expr_op(ast::BinOp::BooleanAnd, expr, cmp))
                                }
                                None => Some(cmp),
                            };
                        }
                        let first = make::ext::ident_path("Self");
                        let second = make::path_from_text(&variant.name()?.to_string());
                        let record_name = make::path_concat(first, second);
                        let list = make::record_pat_field_list(l_fields);
                        let l_record = make::record_pat_with_fields(record_name, list);

                        let first = make::ext::ident_path("Self");
                        let second = make::path_from_text(&variant.name()?.to_string());
                        let record_name = make::path_concat(first, second);
                        let list = make::record_pat_field_list(r_fields);
                        let r_record = make::record_pat_with_fields(record_name, list);

                        let tuple = make::tuple_pat(vec![l_record.into(), r_record.into()]);
                        if let Some(expr) = expr {
                            arms.push(make::match_arm(Some(tuple.into()), None, expr));
                        }
                    }
                    // todo!("implement tuple record iteration")
                    Some(ast::FieldList::TupleFieldList(list)) => {
                        todo!("implement tuple enum iteration")
                    }
                    None => continue,
                }
            }

            if !arms.is_empty() && case_count > arms.len() {
                let lhs = make::wildcard_pat().into();
                arms.push(make::match_arm(Some(lhs), None, make::expr_literal("true").into()));
            }

            let expr = match arms.len() {
                0 => eq_check,
                _ => {
                    let condition = make::condition(eq_check, None);

                    let match_target = make::expr_tuple(vec![self_name, other_name]);
                    let list = make::match_arm_list(arms).indent(ast::edit::IndentLevel(1));
                    let match_expr = Some(make::expr_match(match_target, list));
                    let then_branch = make::block_expr(None, match_expr);
                    let then_branch = then_branch.indent(ast::edit::IndentLevel(1));

                    let else_branche = make::expr_literal("false");
                    let else_branche = make::block_expr(None, Some(else_branche.into()))
                        .indent(ast::edit::IndentLevel(1));

                    make::expr_if(condition, then_branch, Some(else_branche.into()))
                }
            };

            make::block_expr(None, Some(expr)).indent(ast::edit::IndentLevel(1))
        }
        ast::Adt::Struct(strukt) => match strukt.field_list() {
            Some(ast::FieldList::RecordFieldList(field_list)) => {
                let mut expr = None;
                for field in field_list.fields() {
                    let lhs = make::expr_path(make::ext::ident_path("self"));
                    let lhs = make::expr_field(lhs, &field.name()?.to_string());
                    let rhs = make::expr_path(make::ext::ident_path("other"));
                    let rhs = make::expr_field(rhs, &field.name()?.to_string());
                    let cmp = make::expr_op(ast::BinOp::EqualityTest, lhs, rhs);
                    expr = match expr {
                        Some(expr) => Some(make::expr_op(ast::BinOp::BooleanAnd, expr, cmp)),
                        None => Some(cmp),
                    };
                }
                make::block_expr(None, expr).indent(ast::edit::IndentLevel(1))
            }

            Some(ast::FieldList::TupleFieldList(field_list)) => {
                let mut expr = None;
                for (i, _) in field_list.fields().enumerate() {
                    let idx = format!("{}", i);
                    let lhs = make::expr_path(make::ext::ident_path("self"));
                    let lhs = make::expr_field(lhs, &idx);
                    let rhs = make::expr_path(make::ext::ident_path("other"));
                    let rhs = make::expr_field(rhs, &idx);
                    let cmp = make::expr_op(ast::BinOp::EqualityTest, lhs, rhs);
                    expr = match expr {
                        Some(expr) => Some(make::expr_op(ast::BinOp::BooleanAnd, expr, cmp)),
                        None => Some(cmp),
                    };
                }
                make::block_expr(None, expr).indent(ast::edit::IndentLevel(1))
            }

            // No fields in the body means there's nothing to hash.
            None => {
                let expr = make::expr_literal("true").into();
                make::block_expr(None, Some(expr)).indent(ast::edit::IndentLevel(1))
            }
        },
    };

    ted::replace(func.body()?.syntax(), body.clone_for_update().syntax());
    Some(())
}
