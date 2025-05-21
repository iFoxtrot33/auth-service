package jwt

import (
	"AuthService/config"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTData struct {
	Email    string
	Name     string
	Provider string
}

type JWT struct {
	Config *config.Config
}

func NewJWT(cfg *config.Config) *JWT {
	return &JWT{
		Config: cfg,
	}
}

func (j *JWT) CreateAccessToken(data JWTData) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email":    data.Email,
		"name":     data.Name,
		"exp":      time.Now().Unix() + j.Config.Auth.JWT.AccessExpiresIn,
		"provider": data.Provider,
	})

	tokenString, err := token.SignedString([]byte(j.Config.Auth.JWT.Secret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (j *JWT) CreateRefreshToken(data JWTData) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email":    data.Email,
		"name":     data.Name,
		"exp":      time.Now().Unix() + j.Config.Auth.JWT.RefreshExpiresIn,
		"provider": data.Provider,
	})

	tokenString, err := token.SignedString([]byte(j.Config.Auth.JWT.Secret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (j *JWT) Parse(tokenString string) (JWTData, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(j.Config.Auth.JWT.Secret), nil
	})

	if err != nil {
		return JWTData{}, err
	}

	if !token.Valid {
		return JWTData{}, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return JWTData{}, errors.New("invalid claims")
	}

	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return JWTData{}, errors.New("missing or invalid expiration")
	}
	if exp.Before(time.Now()) {
		return JWTData{}, errors.New("token expired")
	}

	email, emailOk := claims["email"].(string)
	name, nameOk := claims["name"].(string)
	provider, providerOk := claims["provider"].(string)
	if !emailOk || !nameOk || !providerOk {
		return JWTData{}, errors.New("missing email, name, or provider in claims")
	}

	return JWTData{
		Email:    email,
		Name:     name,
		Provider: provider,
	}, nil
}
