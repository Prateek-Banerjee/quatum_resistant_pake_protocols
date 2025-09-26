CREATE TABLE "kem_ae_pake" (
	"client_id"	BLOB NOT NULL,
	"protocol_variant"	BLOB NOT NULL,
	"server_state"	BLOB NOT NULL UNIQUE,
    "last_incorrect_login" BLOB,
    "is_client_blocked" INTEGER DEFAULT 0,
	PRIMARY KEY("client_id","protocol_variant")
);

CREATE TABLE "ocake_pake" (
	"client_id"	BLOB NOT NULL,
	"protocol_variant"	BLOB NOT NULL,
	"server_state"	BLOB NOT NULL UNIQUE,
    "last_incorrect_login" BLOB,
    "is_client_blocked" INTEGER DEFAULT 0,
	PRIMARY KEY("client_id","protocol_variant")
);

CREATE TABLE "tk_pake" (
	"client_id"	BLOB NOT NULL,
	"protocol_variant"	BLOB NOT NULL,
	"server_state"	BLOB NOT NULL UNIQUE,
    "last_incorrect_login" BLOB,
    "is_client_blocked" INTEGER DEFAULT 0,
	PRIMARY KEY("client_id","protocol_variant")
);