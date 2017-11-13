package main

func padLeft(str, pad string, length int) string {
	for {
		if len(str) >= length {
			return str
		}
		str = pad + str
	}
}
