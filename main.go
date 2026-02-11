package main

import (
	"gin-auth/internals/initializers"
	"gin-auth/internals/routes"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
	initializers.SyncDatabase()
	initializers.StartBlacklistCleanup()
}

func main() {
	db := initializers.DB
	r := routes.SetupRouter(db)

	r.Run()
}
