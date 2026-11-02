// Package tcpPortScanner проверяет доступность TCP-портов методом обычного
// TCP Connect (без SYN/UDP-сканирования и raw sockets).
//
//	scanner, err := portscan.New(
//		portscan.WithConcurrency(100),
//		portscan.WithConnectTimeout(500*time.Millisecond),
//	)
//	if err != nil {
//		return err
//	}
//	results, err := scanner.Scan(ctx, []string{"192.168.1.10"}, portscan.Range(1, 1000))
//	if err != nil {
//		return err
//	}
//	for r := range results {
//		fmt.Println(r.Host, r.Port, r.State)
//	}
//
// Результаты читайте до закрытия канала либо отмените контекст: пока канал
// не читают, новые подключения не открываются. Scanner безопасен для
// конкурентного использования.
package portsscanner
