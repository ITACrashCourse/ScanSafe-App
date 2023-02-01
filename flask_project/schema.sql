CREATE TABLE Users (
	user_id serial NOT NULL,
	username varchar(64) NOT NULL,
	password varchar(64) NOT NULL,
	email varchar(64) NOT NULL,
	role_id integer NOT NULL,
	created_at TIMESTAMP NOT NULL,
	updated_at TIMESTAMP NOT NULL,
	active BOOLEAN NOT NULL,
	CONSTRAINT Users_pk PRIMARY KEY (user_id)
) WITH (
  OIDS=FALSE
);



CREATE TABLE Roles (
	role_id serial NOT NULL,
	role_name varchar(64) NOT NULL,
	role_description varchar NOT NULL,
	CONSTRAINT Roles_pk PRIMARY KEY (role_id)
) WITH (
  OIDS=FALSE
);



CREATE TABLE Domains (
	domain_id serial NOT NULL,
	domain_name varchar NOT NULL,
	record_created_at DATE NOT NULL,
	record_updated_at TIMESTAMP NOT NULL,
	CONSTRAINT Domains_pk PRIMARY KEY (domain_id)
) WITH (
  OIDS=FALSE
);



CREATE TABLE URL (
	url_id serial NOT NULL,
	domain_id bigint NOT NULL,
	ip_id bigint NOT NULL,
	url varchar NOT NULL,
	record_created_at TIMESTAMP NOT NULL,
	last_scan TIMESTAMP NOT NULL,
	added_by bigint NOT NULL,
	search_counter integer NOT NULL,
	safety_status varchar NOT NULL,
	CONSTRAINT URL_pk PRIMARY KEY (url_id)
) WITH (
  OIDS=FALSE
);



CREATE TABLE IP_address (
	ip_id serial NOT NULL,
	ip_address varchar NOT NULL,
	record_created_at TIMESTAMP NOT NULL,
	record_updated_at TIMESTAMP NOT NULL,
	server varchar NOT NULL,
	category varchar NOT NULL,
	unsafe BOOLEAN NOT NULL,
	risk_score integer NOT NULL,
	age integer NOT NULL,
	suspicious BOOLEAN NOT NULL,
	malware BOOLEAN NOT NULL,
	phising BOOLEAN NOT NULL,
	spamming BOOLEAN NOT NULL,
	parking BOOLEAN NOT NULL,
	dns_server BOOLEAN NOT NULL,
	dns_valid BOOLEAN NOT NULL,
	CONSTRAINT IP_address_pk PRIMARY KEY (ip_id)
) WITH (
  OIDS=FALSE
);



ALTER TABLE Users ADD CONSTRAINT Users_fk0 FOREIGN KEY (role_id) REFERENCES Roles(role_id);



ALTER TABLE URL ADD CONSTRAINT URL_fk0 FOREIGN KEY (domain_id) REFERENCES Domains(domain_id);
ALTER TABLE URL ADD CONSTRAINT URL_fk1 FOREIGN KEY (ip_id) REFERENCES IP_address(ip_id);
ALTER TABLE URL ADD CONSTRAINT URL_fk2 FOREIGN KEY (added_by) REFERENCES Users(user_id);


INSERT INTO 
		roles(
				role_id, role_name, role_description
		)
VALUES
		(1, 'User', 'User account'),
		(2, 'Premium User', 'Premium User account'),
		(3, 'Moderator', 'Moderator account'),
		(4, 'Administrator', 'Administrator account');
