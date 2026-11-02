package portsscanner

import (
	"net"
	"time"
)

// State — итог проверки порта.
type State uint8

const (
	StateUnknown     State = iota // нулевое значение, сканером не возвращается
	StateOpen                     // соединение установлено
	StateClosed                   // соединение отклонено (connection refused)
	StateTimeout                  // не уложились в таймаут подключения
	StateUnreachable              // сеть или узел недоступны
	StateCanceled                 // проверка отменена через context
	StateError                    // другая ошибка, см. Result.Err
)

func (s State) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateClosed:
		return "closed"
	case StateTimeout:
		return "timeout"
	case StateUnreachable:
		return "unreachable"
	case StateCanceled:
		return "canceled"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// Result — результат проверки одного порта одного адреса.
//
// Если DNS-имя не удалось разрешить, приходит один результат на имя:
// Port == 0, IP == nil, State == StateError, errors.Is(Err, ErrResolve).
type Result struct {
	Host     string        // цель в том виде, как её передал пользователь
	IP       net.IP        // адрес, к которому подключались
	Port     uint16        // порт
	State    State         // итог проверки
	Duration time.Duration // длительность попытки подключения
	Err      error         // исходная ошибка (nil для StateOpen)
}
