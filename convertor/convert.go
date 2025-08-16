package convertor

func RunConvert[T any](convertor Convertor[T], data []byte) (T, error) {
	result, err := convertor.Convert(data)
	if err != nil {
		return result, err
	}
	return result, nil
}
