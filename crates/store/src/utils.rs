use crate::SerializableTxid;
use sqlx::types::Uuid;

#[derive(Clone)]
pub struct QueryBuilder {
    sql: String,
    params: Vec<QueryParam>,
}

#[derive(Clone)]
pub enum QueryParam {
    Bool(bool),
    Text(String),
    Int(i64),
    BTCTxid(SerializableTxid),
    Uuid(Uuid),
}

impl QueryBuilder {
    pub fn get_sql(&self) -> String {
        self.sql.clone()
    }

    pub fn get_params(&self) -> Vec<QueryParam> {
        self.params.clone()
    }
    pub fn new(base_sql: &str) -> Self {
        Self { sql: base_sql.to_string(), params: Vec::new() }
    }

    /// Create a new UPDATE query builder
    pub fn update(table: &str) -> Self {
        Self { sql: format!("UPDATE {table}"), params: Vec::new() }
    }

    /// Add SET clause for UPDATE queries
    pub fn set_field(&mut self, field: &str, param: QueryParam) {
        if self.sql.contains("SET") {
            self.sql.push_str(&format!(", {field} = ?"));
        } else {
            self.sql.push_str(&format!(" SET {field} = ?"));
        }
        self.params.push(param);
    }

    /// Add SET clause with NULL value for UPDATE queries
    pub fn set_field_null(&mut self, field: &str) {
        if self.sql.contains("SET") {
            self.sql.push_str(&format!(", {field} = NULL"));
        } else {
            self.sql.push_str(&format!(" SET {field} = NULL"));
        }
    }

    /// Add multiple SET fields for UPDATE queries
    #[allow(dead_code)]
    pub fn set_fields(&mut self, fields: &[(&str, QueryParam)]) {
        for (field, param) in fields {
            self.set_field(field, param.clone());
        }
    }

    pub fn and_where(&mut self, condition: &str, param: Option<QueryParam>) {
        let clause = if self.sql.contains("WHERE") { "AND" } else { "WHERE" };

        self.sql.push_str(&format!(" {clause} {condition}"));

        if let Some(p) = param {
            self.params.push(p);
        }
    }

    /// Add a WHERE condition whose placeholders take several parameters, in order.
    pub fn and_where_params(&mut self, condition: &str, params: Vec<QueryParam>) {
        self.and_where(condition, None);
        self.params.extend(params);
    }

    /// Add WHERE condition with IN clause
    ///
    /// Parameters:
    /// - field: The field name to check
    /// - values: Vector of values to check against
    /// - not_in: If true, use NOT IN instead of IN
    pub fn and_where_in(&mut self, field: &str, values: &[String], not_in: bool) {
        if values.is_empty() {
            return;
        }

        let clause = if self.sql.contains("WHERE") { "AND" } else { "WHERE" };
        let operator = if not_in { "NOT IN" } else { "IN" };
        let placeholders = create_place_holders(values);

        self.sql.push_str(&format!(" {clause} {field} {operator} ({placeholders})"));

        // Add all values as parameters
        for value in values {
            self.params.push(QueryParam::Text(value.clone()));
        }
    }

    /// Add WHERE condition with IN clause for integer values
    ///
    /// Parameters:
    /// - field: The field name to check
    /// - values: Vector of integer values to check against
    /// - not_in: If true, use NOT IN instead of IN
    #[allow(dead_code)]
    pub fn and_where_in_int(&mut self, field: &str, values: &[i64], not_in: bool) {
        if values.is_empty() {
            return;
        }

        let clause = if self.sql.contains("WHERE") { "AND" } else { "WHERE" };
        let operator = if not_in { "NOT IN" } else { "IN" };
        let placeholders = create_place_holders(values);

        self.sql.push_str(&format!(" {clause} {field} {operator} ({placeholders})"));

        // Add all values as parameters
        for value in values {
            self.params.push(QueryParam::Int(*value));
        }
    }

    #[allow(dead_code)]
    pub fn add_raw_condition(&mut self, condition: &str) {
        let clause = if self.sql.contains("WHERE") { "AND" } else { "WHERE" };
        self.sql.push_str(&format!(" {clause} {condition}"));
    }

    pub fn apply_order(&mut self, field: &str) {
        self.sql.push_str(&format!(" ORDER BY {field}"));
    }

    pub fn apply_pagination(&mut self, limit: Option<u32>, offset: Option<u32>) {
        if let Some(limit) = limit {
            self.sql.push_str(&format!(" LIMIT {limit}"));
        }

        if let Some(offset) = offset {
            self.sql.push_str(&format!(" OFFSET {offset}"));
        }
    }

    pub fn query<'q, DB>(
        self,
        mut query: sqlx::query::Query<'q, DB, <DB as sqlx::Database>::Arguments<'q>>,
    ) -> sqlx::query::Query<'q, DB, <DB as sqlx::Database>::Arguments<'q>>
    where
        DB: sqlx::Database,
        for<'a> &'a str: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
        for<'a> String: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
        for<'a> i64: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
        for<'a> bool: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
        for<'a> SerializableTxid: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
        for<'a> u32: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
        for<'a> Uuid: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
    {
        // Bind parameters for query
        for param in self.params {
            query = match param {
                QueryParam::Bool(v) => query.bind(v),
                QueryParam::Text(s) => query.bind(s),
                QueryParam::Int(i) => query.bind(i),
                QueryParam::BTCTxid(btc_txid) => query.bind(btc_txid),
                QueryParam::Uuid(uuid) => query.bind(uuid),
            };
        }
        query
    }

    pub fn query_as<'q, DB, O>(
        self,
        mut query: sqlx::query::QueryAs<'q, DB, O, <DB as sqlx::Database>::Arguments<'q>>,
    ) -> sqlx::query::QueryAs<'q, DB, O, <DB as sqlx::Database>::Arguments<'q>>
    where
        DB: sqlx::Database,
        O: Send + Unpin,
        for<'a> &'a str: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
        for<'a> String: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
        for<'a> i64: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
        for<'a> bool: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
        for<'a> SerializableTxid: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
        for<'a> u32: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
        for<'a> Uuid: sqlx::Encode<'a, DB> + sqlx::Type<DB>,
    {
        // Bind parameters for query
        for param in self.params {
            query = match param {
                QueryParam::Bool(v) => query.bind(v),
                QueryParam::Text(s) => query.bind(s),
                QueryParam::Int(i) => query.bind(i),
                QueryParam::BTCTxid(btc_txid) => query.bind(btc_txid),
                QueryParam::Uuid(uuid) => query.bind(uuid),
            };
        }
        query
    }
}

/// Create placeholders for SQL IN clause
///
/// Creates a string of placeholders like "$1,$2,$3" for use in SQL IN clauses
pub fn create_place_holders<T>(inputs: &[T]) -> String {
    vec!["?"; inputs.len()].join(",")
}
