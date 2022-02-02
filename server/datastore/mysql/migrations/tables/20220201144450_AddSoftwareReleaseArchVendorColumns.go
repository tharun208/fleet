package tables

import (
	"database/sql"
	"fmt"

	"github.com/pkg/errors"
)

func init() {
	MigrationClient.AddMigration(Up_20220201144450, Down_20220201144450)
}

func Up_20220201144450(tx *sql.Tx) error {
	if _, err := tx.Exec("ALTER TABLE software " +
		"ADD COLUMN `vendor` VARCHAR(64) DEFAULT NULL, " +
		"ADD COLUMN `release` VARCHAR(64) DEFAULT NULL, " +
		"ADD COLUMN `arch` VARCHAR(64) DEFAULT NULL"); err != nil {
		return errors.Wrap(err, "add new software columns")
	}

	currIndexName, err := indexNameByColumnName(tx, "software", "name")
	if err != nil {
		return errors.Wrap(err, "fetch current software index")
	}

	if _, err := tx.Exec(fmt.Sprintf("ALTER TABLE software DROP KEY %s", currIndexName)); err != nil {
		return errors.Wrap(err, "add new software columns")
	}

	if _, err := tx.Exec("ALTER TABLE software ADD UNIQUE KEY (name, version, source, vendor, `release`, arch)"); err != nil {
		return errors.Wrap(err, "add new index")
	}

	if _, err := tx.Exec("DELETE FROM software WHERE source = 'rpm_packages'"); err != nil {
		return errors.Wrap(err, "delete existing rpm_packages")
	}

	return nil
}

func Down_20220201144450(tx *sql.Tx) error {
	return nil
}
