package models

import (
	"errors"
	"strings"

	"github.com/badoux/checkmail"
	"github.com/jinzhu/gorm"
)

// Users model
type Users struct {
	gorm.Model
	phoneUser    string `gorm:"type:varchar(15);unique_index"	json:"phoneUser"`
	nameUser     string `gorm:"type:varchar(15);not null"		json:"nameUser"`
	infoUser     string `gorm:"type:text"						json:"infoUser"`
	photoUser    string `gorm:"type:varchar(100);not null"		json:"photoUser"`
	lastseenUser string `gorm:"type:time(6) without time zone"	json:"lastseenUser"`
}

/*
// HashPassword hashes password from user input
func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14) // 14 is the cost for hashing the password.
    return string(bytes), err
}

// CheckPasswordHash checks password hash and password from user input if they match
func CheckPasswordHash(password, hash string) error {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    if err != nil {
        return errors.New("password incorrect")
    }
    return nil
}

// BeforeSave hashes user password
func (u *User) BeforeSave() error {
    password := strings.TrimSpace(u.Password)
    hashedpassword, err := HashPassword(password)
    if err != nil {
        return err
    }
    u.Password = string(hashedpassword)
    return nil
}
*/

// Prepare strips user input of any white spaces
func (u *Users) Prepare() {
	u.phoneUser = strings.TrimSpace(u.phoneUser)
	u.nameUser = strings.TrimSpace(u.nameUser)
	u.infoUser = strings.TrimSpace(u.infoUser)
	u.photoUser = strings.TrimSpace(u.photoUser)
	u.lastseenUser = strings.TrimSpace(u.lastseenUser)
}

// Validate user input
func (u *Users) Validate(action string) error {
	switch strings.ToLower(action) {
	case "login":
		if u.phoneUser == "" {
			return errors.New("Phone Number is required")
		}
		return nil
	default: // this is for creating a user, where all fields are required
		if u.phoneUser == "" {
			return errors.New("PhoneUser is required")
		}
		if u.nameUser == "" {
			return errors.New("NameUser is required")
		}
		if u.infoUser == "" {
			return errors.New("InfoUser is required")
		}
		if u.photoUser == "" {
			return errors.New("PhotoUser is required")
		}
		if u.lastseenUser == "" {
			return errors.New("LastSeenUser is required")
		}
		if err := checkmail.ValidateFormat(u.phoneUser); err != nil {
			return errors.New("Invalid PhoneUser")
		}
		return nil
	}
}

// SaveUser adds a user to the database
func (u *Users) SaveUser(db *gorm.DB) (*Users, error) {
	var err error

	// Debug a single operation, show detailed log for this operation
	err = db.Debug().Create(&u).Error
	if err != nil {
		return &Users{}, err
	}
	return u, nil
}

// GetUser returns a user based on email
func (u *Users) GetUser(db *gorm.DB) (*Users, error) {
	account := &Users{}
	if err := db.Debug().Table("users").Where("email = ?", u.phoneUser).First(account).Error; err != nil {
		return nil, err
	}
	return account, nil
}

// GetAllUsers returns a list of all the user
func GetAllUsers(db *gorm.DB) (*[]Users, error) {
	users := []Users{}
	if err := db.Debug().Table("users").Find(&users).Error; err != nil {
		return &[]Users{}, err
	}
	return &users, nil
}
