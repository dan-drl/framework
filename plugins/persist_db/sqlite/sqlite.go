package sqlite

import (
	"fmt"
	"os"
	"path"

	"github.com/dan-drl/framework/core/global"

	"github.com/jinzhu/gorm"
	"go.elastic.co/apm/module/apmgorm"
	_ "go.elastic.co/apm/module/apmgorm/dialects/sqlite"
)

// SQLiteConfig currently do nothing
type SQLiteConfig struct {
}

// GetInstance return sqlite instance for further access
func GetInstance(cfg *SQLiteConfig) *gorm.DB {
	os.MkdirAll(path.Join(global.Env().GetWorkingDir(), "database/"), 0777)
	fileName := fmt.Sprintf("file:%s?cache=shared&mode=rwc&_busy_timeout=50000000", path.Join(global.Env().GetWorkingDir(), "database/db.sqlite"))

	var err error
	db, err := apmgorm.Open("sqlite3", fileName)
	if err != nil {
		panic("failed to connect database")
	}
	return db
}
