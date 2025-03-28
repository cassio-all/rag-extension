package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/copilot-extensions/rag-extension/agent"
	"github.com/copilot-extensions/rag-extension/config"
	"github.com/copilot-extensions/rag-extension/oauth"
	"github.com/joho/godotenv"
)

func init() {
	// Configurar o token do ngrok automaticamente
	ngrokToken := os.Getenv("NGROK_AUTHTOKEN")
	if ngrokToken != "" {
		cmd := exec.Command("ngrok", "config", "add-authtoken", ngrokToken)
		err := cmd.Run()
		if err != nil {
			log.Fatalf("Erro ao configurar o token do ngrok: %v", err)
		}
	}
}

func main() {
	// Carregar o arquivo .env
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Erro ao carregar o arquivo .env: %v", err)
	}

	// Executar o servidor
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() error {
	// Buscar a chave pública do GitHub
	pubKey, err := fetchPublicKey()
	if err != nil {
		return fmt.Errorf("failed to fetch public key: %w", err)
	}

	// Configurar as variáveis de ambiente
	config, err := config.New()
	if err != nil {
		return fmt.Errorf("error fetching config: %w", err)
	}

	// Configurar o callback do OAuth
	me, err := url.Parse(config.FQDN)
	if err != nil {
		return fmt.Errorf("unable to parse HOST environment variable: %w", err)
	}
	me.Path = "auth/callback"

	// Configurar os serviços de OAuth e agente
	oauthService := oauth.NewService(config.ClientID, config.ClientSecret, me.String())
	http.HandleFunc("/auth/authorization", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Requisição recebida: %s %s", r.Method, r.URL.Path)

		// Gerar um estado aleatório
		state := generateRandomState()

		// Configurar o cookie de estado
		http.SetCookie(w, &http.Cookie{
			Name:     "state",
			Value:    state,
			Path:     "/",
			HttpOnly: true,
			Secure:   strings.HasPrefix(config.FQDN, "https"), // Garantir que seja seguro
		})

		// Redirecionar para o GitHub com o estado
		oauthService.PreAuth(w, r)
	})
	http.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Requisição recebida: %s %s", r.Method, r.URL.Path)

		// Recuperar o cookie de estado
		stateCookie, err := r.Cookie("state")
		if err != nil {
			http.Error(w, "state cookie not found", http.StatusBadRequest)
			return
		}

		// Validar o estado retornado pelo GitHub
		state := r.URL.Query().Get("state")
		if state != stateCookie.Value {
			http.Error(w, "invalid state", http.StatusBadRequest)
			return
		}

		// Continuar com o fluxo de autenticação
		oauthService.PostAuth(w, r)
	})

	agentService := agent.NewService(pubKey)
	http.HandleFunc("/agent", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Requisição recebida: %s %s", r.Method, r.URL.Path)
		agentService.ChatCompletion(w, r)
	})

	// Adicionar uma rota básica para teste
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Requisição recebida: %s %s", r.Method, r.URL.Path)
		fmt.Fprintln(w, "Servidor rodando!")
	})

	// Iniciar o servidor
	log.Printf("Servidor rodando na porta %s...", config.Port)
	return http.ListenAndServe(":"+config.Port, nil)
}

// fetchPublicKey busca as chaves públicas usadas para assinar mensagens do GitHub Copilot
func fetchPublicKey() (*ecdsa.PublicKey, error) {
	resp, err := http.Get("https://api.github.com/meta/public_keys/copilot_api")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch public key: %s", resp.Status)
	}

	var respBody struct {
		PublicKeys []struct {
			Key       string `json:"key"`
			IsCurrent bool   `json:"is_current"`
		} `json:"public_keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	var rawKey string
	for _, pk := range respBody.PublicKeys {
		if pk.IsCurrent {
			rawKey = pk.Key
			break
		}
	}
	if rawKey == "" {
		return nil, fmt.Errorf("could not find current public key")
	}

	pubPemStr := strings.ReplaceAll(rawKey, "\\n", "\n")
	// Decodificar a chave pública
	block, _ := pem.Decode([]byte(pubPemStr))
	if block == nil {
		return nil, fmt.Errorf("error parsing PEM block with GitHub public key")
	}

	// Criar a chave pública ECDSA
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("GitHub key is not ECDSA")
	}

	return ecdsaKey, nil
}

// generateRandomState gera um estado aleatório para proteger contra CSRF
func generateRandomState() string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 16)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
