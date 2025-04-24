package scanning

import "regexp"

// Grepping is function for checking pattern
func Grepping(data, regex string) []string {
	pattern := regexp.MustCompile(regex)
	return pattern.FindAllString(data, -1)
}

// builtinGrep is aether build-in grep pattern
func builtinGrep(data string) map[string][]string {
	return grepPatterns(data, builtinPatterns)
}

// customGrep is user custom grep pattern
func customGrep(data string, pattern map[string]string) map[string][]string {
	return grepPatterns(data, pattern)
}

// grepPatterns is a helper function to grep patterns from data
func grepPatterns(data string, patterns map[string]string) map[string][]string {
	result := make(map[string][]string)
	for k, v := range patterns {
		resultArr := Grepping(data, v)
		if len(resultArr) > 0 {
			result[k] = resultArr
		}
	}
	return result
}

// builtinPatterns is a map of aether built-in grep patterns
var builtinPatterns = map[string]string{
	"aether-ssti":                  "2958816",
	"aether-esii":                  "<esii-aether>",
	"aether-rsa-key":               "-----BEGIN RSA PRIVATE KEY-----|-----END RSA PRIVATE KEY-----",
	"aether-priv-key":              "-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----",
	"aether-aws-s3":                "s3\\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\\.s3\\.amazonaws.com",
	"aether-aws-appsync-graphql":   "da2-[a-z0-9]{26}",
	"aether-slack-webhook1":        "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
	"aether-slack-webhook2":        "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8,10}/B[a-zA-Z0-9_]{8,10}/[a-zA-Z0-9_]{24}",
	"aether-slack-token":           "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
	"aether-facebook-oauth":        "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\\s][0-9a-f]{32}['\"\\s]",
	"aether-twitter-oauth":         "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]",
	"aether-heroku-api":            "[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
	"aether-mailgun-api":           "key-[0-9a-zA-Z]{32}",
	"aether-mailchamp-api":         "[0-9a-f]{32}-us[0-9]{1,2}",
	"aether-picatic-api":           "sk_live_[0-9a-z]{32}",
	"aether-google-oauth-id":       "[0-9(+-[0-9A-Za-z_]{32}.apps.qooqleusercontent.com",
	"aether-google-api":            "AIza[0-9A-Za-z-_]{35}",
	"aether-google-oauth":          "ya29\\.[0-9A-Za-z\\-_]+",
	"aether-aws-access-key":        "AKIA[0-9A-Z]{16}",
	"aether-amazon-mws-auth-token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
	"aether-facebook-access-token": "EAACEdEose0cBA[0-9A-Za-z]+",
	"aether-github-access-token":   "[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*",
	"aether-github":                "[gG][iI][tT][hH][uU][bB].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
	"aether-azure-storage":         "[a-zA-Z0-9_-]*\\.file.core.windows.net",
	"aether-telegram-bot-api-key":  "[0-9]+:AA[0-9A-Za-z\\-_]{33}",
	"aether-square-access-token":   "sq0atp-[0-9A-Za-z\\-_]{22}",
	"aether-square-oauth-secret":   "sq0csp-[0-9A-Za-z\\-_]{43}",
	"aether-twitter-access-token":  "[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
	"aether-twilio-api-key":        "SK[0-9a-fA-F]{32}",
	"aether-braintree-token":       "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
	"aether-stripe-api-key":        "sk_live_[0-9a-zA-Z]{24}",
	"aether-stripe-restricted-key": "rk_live_[0-9a-zA-Z]{24}",
	"aether-error-mysql":           "(SQL syntax.*MySQL|Warning.*mysql_.*|MySqlException \\(0x|valid MySQL result|check the manual that corresponds to your (MySQL|MariaDB) server version|MySqlClient\\.|com\\.mysql\\.jdbc\\.exceptions)",
	"aether-error-postgresql":      "(PostgreSQL.*ERROR|Warning.*\\Wpg_.*|valid PostgreSQL result|Npgsql\\.|PG::SyntaxError:|org\\.postgresql\\.util\\.PSQLException|ERROR:\\s\\ssyntax error at or near)",
	"aether-error-mssql":           "(Driver.* SQL[\\-\\_\\ ]*Server|OLE DB.* SQL Server|\bSQL Server.*Driver|Warning.*mssql_.*|\bSQL Server.*[0-9a-fA-F]{8}|[\\s\\S]Exception.*\\WSystem\\.Data\\.SqlClient\\.|[\\s\\S]Exception.*\\WRoadhouse\\.Cms\\.|Microsoft SQL Native Client.*[0-9a-fA-F]{8})",
	"aether-error-msaccess":        "(Microsoft Access (\\d+ )?Driver|JET Database Engine|Access Database Engine|ODBC Microsoft Access)",
	"aether-error-oracle":          "(\\bORA-\\d{5}|Oracle error|Oracle.*Driver|Warning.*\\Woci_.*|Warning.*\\Wora_.*)",
	"aether-error-ibmdb2":          "(CLI Driver.*DB2|DB2 SQL error|\\bdb2_\\w+\\(|SQLSTATE.+SQLCODE)",
	"aether-error-informix":        "(Exception.*Informix)",
	"aether-error-firebird":        "(Dynamic SQL Error|Warning.*ibase_.*)",
	"aether-error-sqlite":          "(SQLite\\/JDBCDriver|SQLite.Exception|System.Data.SQLite.SQLiteException|Warning.*sqlite_.*|Warning.*SQLite3::|\\[SQLITE_ERROR\\])",
	"aether-error-sapdb":           "(SQL error.*POS([0-9]+).*|Warning.*maxdb.*)",
	"aether-error-sybase":          "(Warning.*sybase.*|Sybase message|Sybase.*Server message.*|SybSQLException|com\\.sybase\\.jdbc)",
	"aether-error-ingress":         "(Warning.*ingres_|Ingres SQLSTATE|Ingres\\W.*Driver)",
	"aether-error-frontbase":       "(Exception (condition )?\\d+. Transaction rollback.)",
	"aether-error-hsqldb":          "(org\\.hsqldb\\.jdbc|Unexpected end of command in statement \\[|Unexpected token.*in statement \\[)",

	//sqli
	/////////////////////////////////////////////////////////

	//mysql
	"aether-error-mysql1":  "SQL syntax.*?MySQL",
	"aether-error-mysql2":  "Warning.*?mysqli?",
	"aether-error-mysql3":  "MySQLSyntaxErrorException",
	"aether-error-mysql4":  "valid MySQL result",
	"aether-error-mysql5":  "check the manual that (corresponds to|fits) your MySQL server version",
	"aether-error-mysql6":  "check the manual that (corresponds to|fits) your MariaDB server version",
	"aether-error-mysql7":  "check the manual that (corresponds to|fits) your Drizzle server version",
	"aether-error-mysql8":  "Unknown column '[^ ]+' in 'field list'",
	"aether-error-mysql9":  "com\\.mysql\\.jdbc",
	"aether-error-mysql10": "Zend_Db_(Adapter|Statement)_Mysqli_Exception",
	"aether-error-mysql11": "MySqlException",
	"aether-error-mysql12": "Syntax error or access violation",

	//psql
	"aether-error-psql1":  "PostgreSQL.*?ERROR",
	"aether-error-psql2":  "Warning.*?\\Wpg_",
	"aether-error-psql3":  "valid PostgreSQL result",
	"aether-error-psql4":  "Npgsql\\.",
	"aether-error-psql5":  "PG::SyntaxError:",
	"aether-error-psql6":  "org\\.postgresql\\.util\\.PSQLException",
	"aether-error-psql7":  "ERROR:\\s\\ssyntax error at or near",
	"aether-error-psql8":  "ERROR: parser: parse error at or near",
	"aether-error-psql9":  "PostgreSQL query failed",
	"aether-error-psql10": "org\\.postgresql\\.jdbc",
	"aether-error-psql11": "PSQLException",

	//mssql
	"aether-error-mssql1":  "Driver.*? SQL[\\-\\_\\ ]*Server",
	"aether-error-mssql2":  "OLE DB.*? SQL Server",
	"aether-error-mssql3":  "\bSQL Server[^&lt;&quot;]+Driver",
	"aether-error-mssql4":  "Warning.*?\\W(mssql|sqlsrv)_",
	"aether-error-mssql5":  "\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
	"aether-error-mssql6":  "System\\.Data\\.SqlClient\\.SqlException",
	"aether-error-mssql7":  "(?s)Exception.*?\\bAether\\.Cms\\.",
	"aether-error-mssql8":  "Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
	"aether-error-mssql9":  "\\[SQL Server\\]",
	"aether-error-mssql10": "ODBC SQL Server Driver",
	"aether-error-mssql11": "ODBC Driver \\d+ for SQL Server",
	"aether-error-mssql12": "SQLServer JDBC Driver",
	"aether-error-mssql13": "com\\.jnetdirect\\.jsql",
	"aether-error-mssql14": "macromedia\\.jdbc\\.sqlserver",
	"aether-error-mssql15": "Zend_Db_(Adapter|Statement)_Sqlsrv_Exception",
	"aether-error-mssql16": "com\\.microsoft\\.sqlserver\\.jdbc",
	"aether-error-mssql18": "SQL(Srv|Server)Exception",
}
