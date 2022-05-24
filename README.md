# GoKalkan

[![pkg-img]][pkg-url]
[![reportcard-img]][reportcard-url]

GoKalkan - это библиотека-обертка над KalkanCrypt для Golang.

KalkanCrypt - это набор библиотек для шифрования, дешифрования данных.

Основные методы KalkanCrypt реализованы в `libkalkancryptwr-64`. Это файл доступными методами
для подписания файлов, текста используя ЭЦП. Подробнее про PKI можно почитать [здесь](wiki/README.md).

## Перед использованием

Чтобы использовать библиотеку требуется провести подготовку:

1. Обратиться в [pki.gov.kz](https://pki.gov.kz/developers/) чтобы получить SDK. Он представляет из себя набор библиотек для Java и C.

2. Установить CA сертификаты.

Сертификаты лежат по пути `SDK/C/Linux/ca-certs/Ubuntu`. Будут два типа сертификатов - `production` и `test`. В папке будут скрипты для установки сертификатов, понадобятся sudo права.

3. Скопировать `libkalkancryptwr-64.so` и `libkalkancryptwr-64.so.1.1.0` в `/usr/lib/`

Файлы лежат в директории `SDK/C/Linux/C`. Команда для копирования:

```sh
sudo cp -f libkalkancryptwr-64.so libkalkancryptwr-64.so.1.1.0 /usr/lib/
```

4. Скопировать `kalkancrypt` в `/opt/`.

`kalkancrypt` - это набор из общих библиотек и состоит из файлов расширения `.so` (англ. "shared object").

Скопируйте папку `SDK/C/Linux/libs_for_linux/kalkancrypt` в `/opt/`

```sh
sudo cp -r kalkancrypt /opt/
```

5. Настроить права доступа `/opt/kalkancrypt`.

```sh
sudo chmod -R 555 /opt/kalkancrypt
```

6. Переменная окружения `LD_LIBRARY_PATH`

При использовании `gokalkan` убедитесь, что экспортирована переменная окружения:

```sh
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/kalkancrypt/:/opt/kalkancrypt/lib/engines
```

Эта переменная нужна для обращения к библиотеке KalkanCrypt.

## Установка

Версия Go 1.17+

```sh
go get github.com/gokalkan/gokalkan
```

## Примеры

Начнем с загрузки сертификатов (можно ЭЦП, который начинается с `RSA...`):

```go
package main

import (
	"fmt"
	"log"

	kalkan "github.com/gokalkan/gokalkan"
)

var (
	// certPath хранит путь к сертификату
	certPath = "test_cert/GOSTKNCA.p12"

	// certPassword пароль
	// P.S. никогда не храните пароли в коде
	certPassword = "Qwerty12"
)

func main() {
	cli, err := kalkan.NewClient()
	if err != nil {
		log.Fatal("NewClient", err)
	}
	// Обязательно закрывайте клиент, иначе приведет утечкам ресурсов
	defer cli.Close()

	// Подгружаем сертификат с паролем
	if err := cli.LoadKeyStore(certPassword, certPath); err != nil {
		log.Fatal("cli.LoadKeyStore", err)
	}
}
```

### Подпись XML документа

Для того чтобы подписать XML документ, нужно передать документ в виде строки:

```go
signedXML, err := cli.SignXML("<root>GoKalkan</root>")

fmt.Println("Подписанный XML", signedXML)
fmt.Println("Ошибка", err)
```

### Проверка подписи на XML документе

Проверка подписи документа вернет ошибку, если документ подписан неверно либо срок
у сертификата с которым подписан истёк.

```go
serial, err := cli.VerifyXML(signedXML)

fmt.Println("Серийный номер", serial)
fmt.Println("Ошибка", err)
```

### Подпись XML документа для SmartBridge

Для того чтобы подписать XML документ в формате SignWSSE, нужно передать документ в виде строки.
Функция обернет документ в `soap:Envelope` и запишет внутри `soap:Body`.

```go
signedXML, err := cli.SignWSSE("<root>GoKalkan</root>")

fmt.Println("Подписанный XML в формате WSSE", signedXML)
fmt.Println("Ошибка", err)
```

## Особенности

Библиотека GoKalkan может работать мультипоточно. Вызовы методов являются concurrency-safe.

Нет зависимостей - zero dependency.

## Бенчмарки

Команда запуска бенчмарка:

```sh
go test -bench SignXML -run=^$ -benchmem
```

Характеристики хост машины:

- goos: linux
- goarch: amd64
- cpu: Intel(R) Core(TM) i5-8500 CPU @ 3.00GHz

| Бенчмарк           | Кол-во циклов | Средн. время выполнения | Средн. потребление ОЗУ | Средн. кол-во аллокаций |
| ------------------ | ------------- | ----------------------- | ---------------------- | ----------------------- |
| BenchmarkSignXML-6 | 2809          | 422310 ns/op            | 2792 B/op              | 8 allocs/op             |

## Contributors ✨

Cпасибо за помощь в развитии проекта:

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->

<table>
	<tr>
		<td align="center">
			<a href="https://github.com/atlekbai">
				<img src="https://avatars.githubusercontent.com/u/29381624?v=4&s=100" width="100px;" alt=""/><br />
				<sub><b>Tlekbai Ali</b></sub>
			</a><br />
			<a href="https://github.com/gokalkan/gokalkan/commits?author=atlekbai" title="Code">💻</a>
		</td>
		<td align="center">
			<a href="https://github.com/gammban">
				<img src="https://avatars.githubusercontent.com/u/98373125?v=4s=100" width="100px;" alt=""/><br />
				<sub><b>Kilibayev Azat</b></sub>
			</a><br />
			<a href="https://github.com/gokalkan/gokalkan/commits?author=gammban" title="Code">💻</a>
		</td>
	</tr>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

## License

The MIT License (MIT) 2021 - [Abylaikhan Zulbukharov](https://github.com/Zulbukharov).

Please have a look at the [LICENSE.md](https://github.com/Zulbukharov/kalkancrypt-wrapper/blob/master/LICENSE.md) for more details.

[pkg-img]: https://pkg.go.dev/badge/Zulbukharov/GoKalkan
[pkg-url]: https://pkg.go.dev/github.com/gokalkan/gokalkan
[reportcard-img]: https://goreportcard.com/badge/Zulbukharov/GoKalkan
[reportcard-url]: https://goreportcard.com/report/Zulbukharov/GoKalkan
