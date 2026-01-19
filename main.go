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
	// Pass the DB instance to the router setup
	db := initializers.DB
	r := routes.SetupRouter(db)

	r.Run()
}
