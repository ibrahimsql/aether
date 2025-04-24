package scanning

import "regexp"

// Grepping is function for checking pattern
func Grepping(data, regex string) []string {
	pattern := regexp.MustCompile(regex)
	return pattern.FindAllString(data, -1)
}

// builtinGrep is aetherxss build-in grep pattern
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

// builtinPatterns is a map of aetherxss built-in grep patterns
var builtinPatterns = map[string]string{
	"aetherxss-ssti":                  "2958816",
	"aetherxss-esii":                  "<esii-aetherxss>",
	"aetherxss-rsa-key":               "-----BEGIN RSA PRIVATE KEY-----|-----END RSA PRIVATE KEY-----",
	"aetherxss-priv-key":              "-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----",
	"aetherxss-aws-s3":                "s3\\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\\.s3\\.amazonaws.com",
	"aetherxss-aws-appsync-graphql":   "da2-[a-z0-9]{26}",
	"aetherxss-slack-webhook1":        "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
	"aetherxss-slack-webhook2":        "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8,10}/B[a-zA-Z0-9_]{8,10}/[a-zA-Z0-9_]{24}",
	"aetherxss-slack-token":           "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
	"aetherxss-facebook-oauth":        "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\\s][0-9a-f]{32}['\"\\s]",
	"aetherxss-twitter-oauth":         "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]",
	"aetherxss-heroku-api":            "[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
	"aetherxss-mailgun-api":           "key-[0-9a-zA-Z]{32}",
	"aetherxss-mailchamp-api":         "[0-9a-f]{32}-us[0-9]{1,2}",
	"aetherxss-picatic-api":           "sk_live_[0-9a-z]{32}",
	"aetherxss-google-oauth-id":       "[0-9(+-[0-9A-Za-z_]{32}.apps.qooqleusercontent.com",
	"aetherxss-google-api":            "AIza[0-9A-Za-z-_]{35}",
	"aetherxss-google-oauth":          "ya29\\.[0-9A-Za-z\\-_]+",
	"aetherxss-aws-access-key":        "AKIA[0-9A-Z]{16}",
	"aetherxss-amazon-mws-auth-token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
	"aetherxss-facebook-access-token": "EAACEdEose0cBA[0-9A-Za-z]+",
	"aetherxss-github-access-token":   "[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*",
	"aetherxss-github":                "[gG][iI][tT][hH][uU][bB].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
	"aetherxss-azure-storage":         "[a-zA-Z0-9_-]*\\.file.core.windows.net",
	"aetherxss-telegram-bot-api-key":  "[0-9]+:AA[0-9A-Za-z\\-_]{33}",
	"aetherxss-square-access-token":   "sq0atp-[0-9A-Za-z\\-_]{22}",
	"aetherxss-square-oauth-secret":   "sq0csp-[0-9A-Za-z\\-_]{43}",
	"aetherxss-twitter-access-token":  "[tT][wW][iI][tT][tT][eE][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
	"aetherxss-twilio-api-key":        "SK[0-9a-fA-F]{32}",
	"aetherxss-braintree-token":       "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
	"aetherxss-stripe-api-key":        "sk_live_[0-9a-zA-Z]{24}",
	"aetherxss-stripe-restricted-key": "rk_live_[0-9a-zA-Z]{24}",
	"aetherxss-error-mysql":           "(SQL syntax.*MySQL|Warning.*mysql_.*|MySqlException \\(0x|valid MySQL result|check the manual that corresponds to your (MySQL|MariaDB) server version|MySqlClient\\.|com\\.mysql\\.jdbc\\.exceptions)",
	"aetherxss-error-postgresql":      "(PostgreSQL.*ERROR|Warning.*\\Wpg_.*|valid PostgreSQL result|Npgsql\\.|PG::SyntaxError:|org\\.postgresql\\.util\\.PSQLException|ERROR:\\s\\ssyntax error at or near)",
	"aetherxss-error-mssql":           "(Driver.* SQL[\\-\\_\\ ]*Server|OLE DB.* SQL Server|\bSQL Server.*Driver|Warning.*mssql_.*|\bSQL Server.*[0-9a-fA-F]{8}|[\\s\\S]Exception.*\\WSystem\\.Data\\.SqlClient\\.|[\\s\\S]Exception.*\\WRoadhouse\\.Cms\\.|Microsoft SQL Native Client.*[0-9a-fA-F]{8})",
	"aetherxss-error-msaccess":        "(Microsoft Access (\\d+ )?Driver|JET Database Engine|Access Database Engine|ODBC Microsoft Access)",
	"aetherxss-error-oracle":          "(\\bORA-\\d{5}|Oracle error|Oracle.*Driver|Warning.*\\Woci_.*|Warning.*\\Wora_.*)",
	"aetherxss-error-ibmdb2":          "(CLI Driver.*DB2|DB2 SQL error|\\bdb2_\\w+\\(|SQLSTATE.+SQLCODE)",
	"aetherxss-error-informix":        "(Exception.*Informix)",
	"aetherxss-error-firebird":        "(Dynamic SQL Error|Warning.*ibase_.*)",
	"aetherxss-error-sqlite":          "(SQLite\\/JDBCDriver|SQLite.Exception|System.Data.SQLite.SQLiteException|Warning.*sqlite_.*|Warning.*SQLite3::|\\[SQLITE_ERROR\\])",
	"aetherxss-error-sapdb":           "(SQL error.*POS([0-9]+).*|Warning.*maxdb.*)",
	"aetherxss-error-sybase":          "(Warning.*sybase.*|Sybase message|Sybase.*Server message.*|SybSQLException|com\\.sybase\\.jdbc)",
	"aetherxss-error-ingress":         "(Warning.*ingres_|Ingres SQLSTATE|Ingres\\W.*Driver)",
	"aetherxss-error-frontbase":       "(Exception (condition )?\\d+. Transaction rollback.)",
	"aetherxss-error-hsqldb":          "(org\\.hsqldb\\.jdbc|Unexpected end of command in statement \\[|Unexpected token.*in statement \\[)",

	//sqli
	/////////////////////////////////////////////////////////

	//mysql
	"aetherxss-error-mysql1":  "SQL syntax.*?MySQL",
	"aetherxss-error-mysql2":  "Warning.*?mysqli?",
	"aetherxss-error-mysql3":  "MySQLSyntaxErrorException",
	"aetherxss-error-mysql4":  "valid MySQL result",
	"aetherxss-error-mysql5":  "check the manual that (corresponds to|fits) your MySQL server version",
	"aetherxss-error-mysql6":  "check the manual that (corresponds to|fits) your MariaDB server version",
	"aetherxss-error-mysql7":  "check the manual that (corresponds to|fits) your Drizzle server version",
	"aetherxss-error-mysql8":  "Unknown column '[^ ]+' in 'field list'",
	"aetherxss-error-mysql9":  "com\\.mysql\\.jdbc",
	"aetherxss-error-mysql10": "Zend_Db_(Adapter|Statement)_Mysqli_Exception",
	"aetherxss-error-mysql11": "MySqlException",
	"aetherxss-error-mysql12": "Syntax error or access violation",

	//psql
	"aetherxss-error-psql1":  "PostgreSQL.*?ERROR",
	"aetherxss-error-psql2":  "Warning.*?\\Wpg_",
	"aetherxss-error-psql3":  "valid PostgreSQL result",
	"aetherxss-error-psql4":  "Npgsql\\.",
	"aetherxss-error-psql5":  "PG::SyntaxError:",
	"aetherxss-error-psql6":  "org\\.postgresql\\.util\\.PSQLException",
	"aetherxss-error-psql7":  "ERROR:\\s\\ssyntax error at or near",
	"aetherxss-error-psql8":  "ERROR: parser: parse error at or near",
	"aetherxss-error-psql9":  "PostgreSQL query failed",
	"aetherxss-error-psql10": "org\\.postgresql\\.jdbc",
	"aetherxss-error-psql11": "PSQLException",

	//mssql
	"aetherxss-error-mssql1":  "Driver.*? SQL[\\-\\_\\ ]*Server",
	"aetherxss-error-mssql2":  "OLE DB.*? SQL Server",
	"aetherxss-error-mssql3":  "\bSQL Server[^&lt;&quot;]+Driver",
	"aetherxss-error-mssql4":  "Warning.*?\\W(mssql|sqlsrv)_",
	"aetherxss-error-mssql5":  "\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
	"aetherxss-error-mssql6":  "System\\.Data\\.SqlClient\\.SqlException",
	"aetherxss-error-mssql7":  "(?s)Exception.*?\\bAether\\.Cms\\.",
	"aetherxss-error-mssql8":  "Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
	"aetherxss-error-mssql9":  "\\[SQL Server\\]",
	"aetherxss-error-mssql10": "ODBC SQL Server Driver",
	"aetherxss-error-mssql11": "ODBC Driver \\d+ for SQL Server",
	"aetherxss-error-mssql12": "SQLServer JDBC Driver",
	"aetherxss-error-mssql13": "com\\.jnetdirect\\.jsql",
	"aetherxss-error-mssql14": "macromedia\\.jdbc\\.sqlserver",
	"aetherxss-error-mssql15": "Zend_Db_(Adapter|Statement)_Sqlsrv_Exception",
	"aetherxss-error-mssql16": "com\\.microsoft\\.sqlserver\\.jdbc",
	"aetherxss-error-mssql18": "SQL(Srv|Server)Exception",
}
