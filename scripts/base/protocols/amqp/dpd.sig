signature dpd_amqp {
	ip-proto == tcp
	payload /^AMQP\x00\x00\x09\x01/
	enable "AMQP"
}
