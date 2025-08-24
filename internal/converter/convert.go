package converter

func RunConvert[R SupportedReturnTypes, P SupportedParamsTypes](converter Converter[R, P], data P) (R, error) {
	result, err := converter.Convert(data)
	if err != nil {
		return result, err
	}
	return result, nil
}
