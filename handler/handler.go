package handler

import (
	"a21hc3NpZ25tZW50/client"
	"a21hc3NpZ25tZW50/model"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

var UserLogin = make(map[string]model.User)

// DESC: func Auth is a middleware to check user login id, only user that already login can pass this middleware
func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("user_login_id")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: err.Error()})
			return
		}

		if _, ok := UserLogin[c.Value]; !ok || c.Value == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login id not found"})
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, "userID", c.Value)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// DESC: func AuthAdmin is a middleware to check user login role, only admin can pass this middleware
func AuthAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// your code here }) // TODO: replace this
		c, err := r.Cookie("user_login_id")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: err.Error()})
			return
		}

		if _, ok := UserLogin[c.Value]; !ok || c.Value == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login id not found"})
			return
		}

		roleCookie, err := r.Cookie("user_login_role")
		if err != nil || roleCookie.Value != "admin" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login role not Admin"})
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, "userID", c.Value)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func Login(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        w.WriteHeader(http.StatusMethodNotAllowed)
        json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Method is not allowed!"})
        return
    }

    var user model.User
    err := json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Invalid request body"})
        return
    }

    if user.ID == "" || user.Name == "" {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(model.ErrorResponse{Error: "ID or name is empty"})
        return
    }

    userData, err := os.ReadFile("data/users.txt")
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Internal server error"})
        return
    }

    var userExists bool
	var role string
    for _, line := range strings.Split(string(userData), "\n") {
        if strings.HasPrefix(line, user.ID+"_") {
            userExists = true
			fields := strings.Split(line, "_")
            role = fields[3]
            break
        }
    }

    if !userExists {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user not found"})
        return
    }

    http.SetCookie(w, &http.Cookie{Name: "user_login_id", Value: user.ID})
    http.SetCookie(w, &http.Cookie{Name: "user_login_role", Value: role})

    UserLogin[user.ID] = user

    json.NewEncoder(w).Encode(model.SuccessResponse{
		Username: user.Name,
		Message: "login success"})
}


func Register(w http.ResponseWriter, r *http.Request) {
	// TODO: answer here
	// Memeriksa apakah metodenya adalah POST
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Method is not allowed!"})
		return
	}
	// Membaca body request dan memasukkannya ke variabel user
	var user model.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Body request tidak valid"})
		return
	}

	// Memeriksa apakah ID, nama, atau study kosong
	if user.ID == "" || user.Name == "" || user.Role == "" || user.StudyCode == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "ID, name, study code or role is empty"})
		return
	}
	if user.Role != "admin" && user.Role != "user" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "role must be admin or user"})
		return
	}

	// Memeriksa apakah kode study sudah ada di file
	studyData, err := os.ReadFile("data/list-study.txt")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Internal server error"})
		return
	}
	var studyExist bool
	for _, line := range strings.Split(string(studyData), "\n") {
		if strings.HasPrefix(line, user.StudyCode+"_") {
			studyExist = true
			break
		}
	}
	if !studyExist {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "study code not found"})
		return
	}

	// Memeriksa apakah ID user sudah ada di file
	users, err := os.ReadFile("data/users.txt")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Internal server error"})
		return
	}
	lines := strings.Split(string(users), "\n")
	for _, line := range lines {
		fields := strings.Split(line, "_")
		if len(fields) == 4 && fields[0] == user.ID {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user id already exist"})
			return
		}
	}

	// Menambahkan user ke file
	f, err := os.OpenFile("data/users.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s_%s_%s_%s\n", user.ID, user.Name, user.StudyCode, user.Role)
	if err != nil {
		panic(err)
	}

	// Mengembalikan respons sukses
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(model.SuccessResponse{
		Username: user.ID,
		Message:  "register success",
	})
}

func Logout(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(string)

	// TODO: answer here
	// Mencari cookie user_login_id
	idCookie, err := r.Cookie("user_login_id")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login id not found"})
		return
	}

	// Mencari cookie user_login_role
	roleCookie, err := r.Cookie("user_login_role")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login role not found"})
		return
	}

	// Menghapus cookie user_login_id
	idCookie.MaxAge = -1
	http.SetCookie(w, idCookie)

	// Menghapus cookie user_login_role
	roleCookie.MaxAge = -1
	http.SetCookie(w, roleCookie)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(model.SuccessResponse{
		Username: userID,
		Message:  "logout success",
	})
}

func GetStudyProgram(w http.ResponseWriter, r *http.Request) {
	// list study program
	// TODO: answer here
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Method is not allowed!"})
		return
	}
	// Check if user is logged in
	_, err := r.Cookie("user_login_id")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login id not found"})
		return
	}
	// Membaca file list-study.txt
	studyData, err := os.ReadFile("data/list-study.txt")
	if err != nil {
		// Jika gagal membaca, kirim HTTP status code 500 dan pesan error
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Internal Server Error"})
		return
	}
	// Buat slice untuk menampung data program studi
	var studies []model.StudyData
	lines := strings.Split(string(studyData), "\n")
	// Looping untuk memisahkan kode program studi dan namanya
	for _, line := range lines {
		fields := strings.Split(line, "_")
		if len(fields) == 2 {
			study := model.StudyData{
				Code: fields[0],
				Name: fields[1],
			}
			studies = append(studies, study)
		}
	}
	// Kirim HTTP status code 200 dan data program studi dalam format JSON
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(studies)
}

func AddUser(w http.ResponseWriter, r *http.Request) {
	// TODO: answer here
	// Memeriksa apakah metodenya adalah POST
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Method is not allowed!"})
		return
	}
	// Membaca body request dan memasukkannya ke variabel user
	var user model.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Body request tidak valid"})
		return
	}

	// Memeriksa apakah ID, nama, atau study kosong
	if user.ID == "" || user.Name == "" || user.StudyCode == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "ID, name, or study code is empty"})
		return
	}

	// Memeriksa apakah ID user sudah ada di file
	users, err := os.ReadFile("data/list-study.txt")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Internal server error"})
		return
	}
	lines := strings.Split(string(users), "\n")
	for _, line := range lines {
		fields := strings.Split(line, "_")
		if len(fields) == 2 && fields[0] == user.StudyCode {
			if strings.Contains(line, user.ID) {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user id already exist"})
				return
			}
		}
	}

	// Memeriksa apakah kode study sudah ada di file
	studyData, err := os.ReadFile("data/list-study.txt")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Internal server error"})
		return
	}
	var studyExist bool
	for _, line := range strings.Split(string(studyData), "\n") {
		if strings.HasPrefix(line, user.StudyCode+"_") {
			studyExist = true
			break
		}
	}
	if !studyExist {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "study code not found"})
		return
	}

	// Menambahkan user ke file
	f, err := os.OpenFile("data/users.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s,%s,%s\n", user.ID, user.Name, user.StudyCode)
	if err != nil {
		panic(err)
	}

	// Mengembalikan respons sukses
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(model.SuccessResponse{
		Username: user.ID,
		Message:  "add user success",
	})
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	// TODO: answer here
	// Cek apakah method yang digunakan adalah DELETE
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Method is not allowed!"})
		return
	}

	// Check if user is logged in
	_, err := r.Cookie("user_login_id")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login id not found"})
		return
	}
	// Check if user has admin role
	roleCookie, err := r.Cookie("user_login_role")
	if err != nil || roleCookie.Value != "admin" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login role not Admin"})
		return
	}

	// Ambil ID user dari parameter query URL
	userID := r.URL.Query().Get("id")
	if userID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user id is empty"})
		return
	}

	// Baca data list user
	usersData, err := os.ReadFile("data/users.txt")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Internal server error"})
		return
	}

	// Cari user yang akan dihapus
	lines := strings.Split(string(usersData), "\n")
	var found bool
	var newLines []string
	for _, line := range lines {
		fields := strings.Split(line, ",")
		if len(fields) == 3 && fields[0] == userID {
			found = true
			continue
		}
		if line != "" {
			newLines = append(newLines, line)
		}
	}
	if !found {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user id not found"})
		return
	}

	// Tulis list user yang telah diperbarui ke file
	newData := []byte(strings.Join(newLines, "\n"))
	err = os.WriteFile("data/users.txt", newData, 0644)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Internal server error"})
		return
	}

	// Mengembalikan respons yang sukses
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(model.SuccessResponse{
		Username: userID,
		Message:  "delete success",
	})
}

// DESC: Gunakan variable ini sebagai goroutine di handler GetWeather
var GetWetherByRegionAPI = client.GetWeatherByRegion

func GetWeather(w http.ResponseWriter, r *http.Request) {
	var listRegion = []string{"jakarta", "bandung", "surabaya", "yogyakarta", "medan", "makassar", "manado", "palembang", "semarang", "bali"}

	var resCh = make(chan model.MainWeather, len(listRegion))
	var errCh = make(chan error, len(listRegion))

	for _, region := range listRegion {
		go func(resCh chan model.MainWeather, region string) {
			weather, err := GetWetherByRegionAPI(region)
			if err != nil {
				errCh <- err
			} else {
				resCh <- weather
			}

		}(resCh, region)
	}

	var weathers []model.MainWeather

	for i := 0; i < len(listRegion); i++ {
		select {
		case weather := <-resCh:
			weathers = append(weathers, weather)
		case err := <-errCh:
			errorMessage := model.ErrorResponse{Error: err.Error()}
			errorMessageJson, _ := json.Marshal(errorMessage)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(errorMessageJson)
			return
		}
	}

	weatherJSON, _ := json.Marshal(weathers)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(weatherJSON)

}
