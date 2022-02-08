package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"rbacCustom/controller"
	"rbacCustom/dbops"
	"rbacCustom/utils"
	"strings"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
)

var (
	r   *chi.Mux
	err error
)

type Permission struct {
	Perms []string
}

func init() {
	err = dbops.ConnectDB()
	if err != nil {
		log.Fatal("Error in connectdb", err)
	}

	createMap()
}

var policy = make(map[string]string)
var rel = make(map[string]string)

func createMap() {
	file, err := os.Open("permission.csv")
	if err != nil {
		log.Println(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		pl := strings.Split(scanner.Text(), ",")
		if _, ok := policy[pl[0]]; ok {
			policy[pl[0]] = policy[pl[0]] + "," + pl[1]
		} else {
			policy[pl[0]] = pl[1]
		}

	}

	println(policy["owner"])
	println(policy["manager"])

	file2, err := os.Open("rel.csv")
	if err != nil {
		log.Println(err)
	}
	defer file2.Close()
	scanner2 := bufio.NewScanner(file2)

	scanner2.Split(bufio.ScanLines)

	for scanner2.Scan() {
		pl := strings.Split(scanner2.Text(), ",")
		if _, ok := rel[pl[0]]; ok {
			rel[pl[0]] = rel[pl[0]] + "," + pl[1]
		} else {
			rel[pl[0]] = pl[1]
		}

	}
	// print(rel["owner"])
}
func main() {
	r = chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hi"))
	})

	r.Post("/signup", controller.Signup)
	r.Post("/signin", controller.Signin)

	r.Route("/", func(r chi.Router) {
		r.Use(Authorizer())
		r.Post("/createPaymentsLinks", controller.CreatePayment)
		r.Post("/viewPaymentsLinks", controller.ViewPayment)
		r.Post("/addUser", controller.AddUser)
		r.Post("/changeRoles", controller.ChangeRoles)
		r.Post("/removeUser", controller.RemoveUser)
		r.Post("/viewEscrows", controller.ViewEscrows)
		r.Post("/createPaymentsLinks", controller.CreatePayment)
		r.Post("/viewPaymentsLinks", controller.ViewPayment)
		r.Post("/generateKeys", controller.GenerateKeys)
		r.Post("/kyb", controller.GenerateKeys)
	})

	http.ListenAndServe(":3333", r)
}

func Authorizer() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			group, _, err := utils.ExtractTokenMetadata(r)
			fmt.Println("err middleware", err)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			ok := CheckRole(group, r.URL.Path)
			if !ok {
				fmt.Println("ok failed")
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

func CheckRole(role, path string) bool {
	val, ok := policy[role]
	x := false
	if ok {
		x = stringInSlice(path, strings.Split(val, ","))
	}
	fmt.Println("xvalue", x)
	if x {
		return x
	}
	return checkExistInChild(role, path, strings.Split(val, ","))
}

func checkExistInChild(role, path string, pathList []string) bool {
	if val, ok := rel[role]; ok {
		if strings.Contains(val, ",") {
			return CheckForMultipleChild(val)
		} else {
			return stringInSlice(path, strings.Split(policy[val], ","))
		}
	}
	return false
}

func CheckForMultipleChild(val string) bool {
	id := strings.Split(val, ",")
	for i := 0; i < len(id); i++ {
		a := id[i]
		if stringInSlice(a, strings.Split(policy[a], ",")) {
			return true
		}
	}
	return false
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
