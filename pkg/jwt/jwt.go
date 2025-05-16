package jwt

import (
	"AuthService/config"
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

type JWTData struct {
	Email string
	Name  string
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
		"email": data.Email,
		"name":  data.Name,
		"exp":   j.Config.Auth.JWT.AccessExpiresIn,
	})

	tokenString, err := token.SignedString([]byte(j.Config.Auth.JWT.Secret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (j *JWT) CreateRefreshToken() (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": j.Config.Auth.JWT.RefreshExpiresIn,
	})

	tokenString, err := token.SignedString([]byte(j.Config.Auth.JWT.Secret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (j *JWT) Parse(tokenString string) (bool, *JWTData, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(j.Config.Auth.JWT.Secret), nil
	})

	if err != nil {
		return false, &JWTData{}, err
	}

	if !token.Valid {
		return false, &JWTData{}, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false, &JWTData{}, errors.New("invalid claims")
	}

	email, emailOk := claims["email"]
	name, nameOk := claims["name"]
	if !emailOk && !nameOk {
		return true, &JWTData{}, nil
	}

	if !emailOk || !nameOk {
		return false, &JWTData{}, errors.New("missing email or name in claims")
	}

	return true, &JWTData{
		Email: email.(string),
		Name:  name.(string),
	}, nil
}
