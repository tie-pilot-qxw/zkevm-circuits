// csv2html
// Copyright (c) 2013, 2014, 2017, 2020 D. Bohdan.
// License: BSD (3-clause).  See the file LICENSE.

pub fn escape(s: &str) -> String {
    s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
}

fn tag_with_attrs<S: AsRef<str>>(tag: S, attrs: S) -> String {
    if attrs.as_ref() == "" {
        format!("<{}>", tag.as_ref())
    } else {
        format!("<{} {}>", tag.as_ref(), attrs.as_ref())
    }
}

pub fn prologue<S: AsRef<str>>(title: S) -> String {
    format!(
        "<!DOCTYPE html>\n<html>\n<head><title>{}</title><style> {} </style></head>\n<body>\n",
        escape(title.as_ref()),
        "table { border-collapse: collapse; margin: 0 auto; position: relative; } \
        th, td { border: 1px solid black; padding: 4px; text-align: center; white-space: nowrap; text-overflow:ellipsis; overflow: hidden; max-width:5em; } \
        th { background-color: #f2f2f2; position: sticky; top: 0; } \
        div:not(:last-child) { margin-bottom: 5em; } \
        div { max-height: 60em; overflow: auto; }"
    )
}

pub fn epilogue() -> String {
    "</body>\n</html>\n".to_string()
}

pub fn start<S: AsRef<str>>(table_attrs: S) -> String {
    let mut s = String::new();

    s.push_str(&tag_with_attrs("div", ""));
    s.push('\n');
    s.push_str(&tag_with_attrs("table", table_attrs.as_ref()));
    s.push('\n');

    s
}

pub fn caption<S: AsRef<str>>(caption: S) -> String {
    format!(
        "<caption style=\"text-align:left\">{}</caption>",
        caption.as_ref()
    )
}

pub fn end() -> String {
    "</table>\n</div>\n".to_string()
}

pub fn row<S: AsRef<str>>(cols: &[S], header: bool, row_attrs: S, col_attrs: &[S]) -> String {
    let col_tag = if header { "th" } else { "td" };

    let mut s = String::new();

    s.push_str(&tag_with_attrs("tr", row_attrs.as_ref()));

    for (col, col_attrs) in cols.into_iter().zip(
        col_attrs
            .into_iter()
            .map(|x| x.as_ref())
            .chain(std::iter::repeat("")),
    ) {
        s.push_str(&format!(
            "{}{}</{}>",
            &tag_with_attrs(col_tag, col_attrs),
            &escape(col.as_ref()),
            &col_tag
        ));
    }

    s.push_str("</tr>\n");

    s
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_start_1() {
        assert_eq!(start("x=y"), "<div>\n<table x=y>\n");
    }

    #[test]
    fn test_end() {
        assert_eq!(end(), "</table>\n</div>\n");
    }

    #[test]
    fn test_row_1() {
        assert_eq!(
            row(&vec!["foo", "bar", "baz"], false, "", &[]),
            "<tr><td>foo</td><td>bar</td><td>baz</td></tr>\n"
        )
    }

    #[test]
    fn test_row_2() {
        assert_eq!(
            row(&vec!["one", "two"], true, "x=1", &["y=2", "y=2"]),
            "<tr x=1><th y=2>one</th><th y=2>two</th></tr>\n"
        )
    }
}
