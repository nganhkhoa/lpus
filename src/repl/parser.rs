use pest::{iterators::Pair, Parser};

#[derive(Parser)]
#[grammar = "lpus.pest"]
pub struct LpusParser;

fn is_bracket_or_eoi(parsed: &Pair<Rule>) -> bool {
    if parsed.as_rule() == Rule::EOI {
        return true;
    }
    let c = parsed.as_str();
    c == "(" || c == ")" || c == "{" || c == "}"
}

// Read a rule with children into the given containing Lval
fn read_to_lval(mut v: &mut Lval, parsed: Pair<Rule>) -> Result<()> {
    for child in parsed.into_inner() {
        if is_bracket_or_eoi(&child) {
            continue;
        }
        lval_add(&mut v, &*lval_read(child)?)?;
    }
    Ok(())
}

fn lval_read(parsed: Pair<Rule>) -> ReplResult {
    match parsed.as_rule() {
        // Rule::program => {
        //     let mut ret = lval_lpus();
        //     read_to_lval(&mut ret, parsed)?;
        //     Ok(ret)
        // }
        // Rule::expr => lval_read(parsed.into_inner().next().unwrap()),
        Rule::sexpr => {
            let mut ret = lval_sexpr();
            read_to_lval(&mut ret, parsed)?;
            Ok(ret)
        }
        // Rule::qexpr => {
        //     let mut ret = lval_qexpr();
        //     read_to_lval(&mut ret, parsed)?;
        //     Ok(ret)
        // }
        Rule::num => Ok(lval_num(parsed.as_str().parse::<i64>()?)),
        Rule::symbol => Ok(lval_sym(parsed.as_str())),
        _ => unreachable!(), // COMMENT/WHITESPACE etc
    }
}

pub fn eval_str(e: &mut Lenv, s: &str) -> ReplResult {
    let parsed = LpusParser::parse(Rule::sexpr, s)?.next().unwrap();
    // debug!("{}", parsed);
    let mut lval_ptr = lval_read(parsed)?;
    // debug!("Parsed: {:?}", *lval_ptr);
    lval_eval(e, &mut *lval_ptr)
}
