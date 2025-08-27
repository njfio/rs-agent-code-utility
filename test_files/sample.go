// Go sample file for testing
package main

import (
    "fmt"
    "log"
    "net/http"
)

// User represents a user in the system
type User struct {
    ID    int    `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
}

// UserService handles user operations
type UserService struct {
    users []User
}

// NewUserService creates a new UserService
func NewUserService() *UserService {
    return &UserService{
        users: make([]User, 0),
    }
}

// AddUser adds a new user to the service
func (s *UserService) AddUser(user User) {
    s.users = append(s.users, user)
}

// GetUser retrieves a user by ID
func (s *UserService) GetUser(id int) (*User, error) {
    for _, user := range s.users {
        if user.ID == id {
            return &user, nil
        }
    }
    return nil, fmt.Errorf("user with ID %d not found", id)
}

// GetAllUsers returns all users
func (s *UserService) GetAllUsers() []User {
    return s.users
}

// validateUser checks if a user is valid
func (s *UserService) validateUser(user User) bool {
    return user.ID > 0 && len(user.Name) > 0 && len(user.Email) > 0
}

// CreateUser creates a new user
func CreateUser(name, email string) User {
    return User{
        ID:    generateID(),
        Name:  name,
        Email: email,
    }
}

// generateID generates a random ID
func generateID() int {
    return 42 // simplified for demo
}

func main() {
    service := NewUserService()
    
    user := CreateUser("John Doe", "john@example.com")
    service.AddUser(user)
    
    fmt.Printf("Added user: %+v\n", user)
    
    if foundUser, err := service.GetUser(user.ID); err == nil {
        fmt.Printf("Found user: %+v\n", *foundUser)
    } else {
        log.Printf("Error: %v", err)
    }
}
