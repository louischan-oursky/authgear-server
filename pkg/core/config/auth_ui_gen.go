package config

// Code generated by github.com/tinylib/msgp DO NOT EDIT.

import (
	"github.com/tinylib/msgp/msgp"
)

// DecodeMsg implements msgp.Decodable
func (z *AuthUIConfiguration) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zb0001 uint32
	zb0001, err = dc.ReadMapHeader()
	if err != nil {
		err = msgp.WrapError(err)
		return
	}
	for zb0001 > 0 {
		zb0001--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		switch msgp.UnsafeString(field) {
		case "css":
			z.CSS, err = dc.ReadString()
			if err != nil {
				err = msgp.WrapError(err, "CSS")
				return
			}
		case "country_calling_code":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					err = msgp.WrapError(err, "CountryCallingCode")
					return
				}
				z.CountryCallingCode = nil
			} else {
				if z.CountryCallingCode == nil {
					z.CountryCallingCode = new(AuthUICountryCallingCodeConfiguration)
				}
				var zb0002 uint32
				zb0002, err = dc.ReadMapHeader()
				if err != nil {
					err = msgp.WrapError(err, "CountryCallingCode")
					return
				}
				for zb0002 > 0 {
					zb0002--
					field, err = dc.ReadMapKeyPtr()
					if err != nil {
						err = msgp.WrapError(err, "CountryCallingCode")
						return
					}
					switch msgp.UnsafeString(field) {
					case "values":
						var zb0003 uint32
						zb0003, err = dc.ReadArrayHeader()
						if err != nil {
							err = msgp.WrapError(err, "CountryCallingCode", "Values")
							return
						}
						if cap(z.CountryCallingCode.Values) >= int(zb0003) {
							z.CountryCallingCode.Values = (z.CountryCallingCode.Values)[:zb0003]
						} else {
							z.CountryCallingCode.Values = make([]string, zb0003)
						}
						for za0001 := range z.CountryCallingCode.Values {
							z.CountryCallingCode.Values[za0001], err = dc.ReadString()
							if err != nil {
								err = msgp.WrapError(err, "CountryCallingCode", "Values", za0001)
								return
							}
						}
					case "default":
						z.CountryCallingCode.Default, err = dc.ReadString()
						if err != nil {
							err = msgp.WrapError(err, "CountryCallingCode", "Default")
							return
						}
					default:
						err = dc.Skip()
						if err != nil {
							err = msgp.WrapError(err, "CountryCallingCode")
							return
						}
					}
				}
			}
		case "metadata":
			var zb0004 uint32
			zb0004, err = dc.ReadMapHeader()
			if err != nil {
				err = msgp.WrapError(err, "Metadata")
				return
			}
			if z.Metadata == nil {
				z.Metadata = make(AuthUIMetadataConfiguration, zb0004)
			} else if len(z.Metadata) > 0 {
				for key := range z.Metadata {
					delete(z.Metadata, key)
				}
			}
			for zb0004 > 0 {
				zb0004--
				var za0002 string
				var za0003 interface{}
				za0002, err = dc.ReadString()
				if err != nil {
					err = msgp.WrapError(err, "Metadata")
					return
				}
				za0003, err = dc.ReadIntf()
				if err != nil {
					err = msgp.WrapError(err, "Metadata", za0002)
					return
				}
				z.Metadata[za0002] = za0003
			}
		default:
			err = dc.Skip()
			if err != nil {
				err = msgp.WrapError(err)
				return
			}
		}
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z *AuthUIConfiguration) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 3
	// write "css"
	err = en.Append(0x83, 0xa3, 0x63, 0x73, 0x73)
	if err != nil {
		return
	}
	err = en.WriteString(z.CSS)
	if err != nil {
		err = msgp.WrapError(err, "CSS")
		return
	}
	// write "country_calling_code"
	err = en.Append(0xb4, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79, 0x5f, 0x63, 0x61, 0x6c, 0x6c, 0x69, 0x6e, 0x67, 0x5f, 0x63, 0x6f, 0x64, 0x65)
	if err != nil {
		return
	}
	if z.CountryCallingCode == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		// map header, size 2
		// write "values"
		err = en.Append(0x82, 0xa6, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73)
		if err != nil {
			return
		}
		err = en.WriteArrayHeader(uint32(len(z.CountryCallingCode.Values)))
		if err != nil {
			err = msgp.WrapError(err, "CountryCallingCode", "Values")
			return
		}
		for za0001 := range z.CountryCallingCode.Values {
			err = en.WriteString(z.CountryCallingCode.Values[za0001])
			if err != nil {
				err = msgp.WrapError(err, "CountryCallingCode", "Values", za0001)
				return
			}
		}
		// write "default"
		err = en.Append(0xa7, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74)
		if err != nil {
			return
		}
		err = en.WriteString(z.CountryCallingCode.Default)
		if err != nil {
			err = msgp.WrapError(err, "CountryCallingCode", "Default")
			return
		}
	}
	// write "metadata"
	err = en.Append(0xa8, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61)
	if err != nil {
		return
	}
	err = en.WriteMapHeader(uint32(len(z.Metadata)))
	if err != nil {
		err = msgp.WrapError(err, "Metadata")
		return
	}
	for za0002, za0003 := range z.Metadata {
		err = en.WriteString(za0002)
		if err != nil {
			err = msgp.WrapError(err, "Metadata")
			return
		}
		err = en.WriteIntf(za0003)
		if err != nil {
			err = msgp.WrapError(err, "Metadata", za0002)
			return
		}
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *AuthUIConfiguration) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 3
	// string "css"
	o = append(o, 0x83, 0xa3, 0x63, 0x73, 0x73)
	o = msgp.AppendString(o, z.CSS)
	// string "country_calling_code"
	o = append(o, 0xb4, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79, 0x5f, 0x63, 0x61, 0x6c, 0x6c, 0x69, 0x6e, 0x67, 0x5f, 0x63, 0x6f, 0x64, 0x65)
	if z.CountryCallingCode == nil {
		o = msgp.AppendNil(o)
	} else {
		// map header, size 2
		// string "values"
		o = append(o, 0x82, 0xa6, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73)
		o = msgp.AppendArrayHeader(o, uint32(len(z.CountryCallingCode.Values)))
		for za0001 := range z.CountryCallingCode.Values {
			o = msgp.AppendString(o, z.CountryCallingCode.Values[za0001])
		}
		// string "default"
		o = append(o, 0xa7, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74)
		o = msgp.AppendString(o, z.CountryCallingCode.Default)
	}
	// string "metadata"
	o = append(o, 0xa8, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61)
	o = msgp.AppendMapHeader(o, uint32(len(z.Metadata)))
	for za0002, za0003 := range z.Metadata {
		o = msgp.AppendString(o, za0002)
		o, err = msgp.AppendIntf(o, za0003)
		if err != nil {
			err = msgp.WrapError(err, "Metadata", za0002)
			return
		}
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *AuthUIConfiguration) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zb0001 uint32
	zb0001, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		err = msgp.WrapError(err)
		return
	}
	for zb0001 > 0 {
		zb0001--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		switch msgp.UnsafeString(field) {
		case "css":
			z.CSS, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "CSS")
				return
			}
		case "country_calling_code":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.CountryCallingCode = nil
			} else {
				if z.CountryCallingCode == nil {
					z.CountryCallingCode = new(AuthUICountryCallingCodeConfiguration)
				}
				var zb0002 uint32
				zb0002, bts, err = msgp.ReadMapHeaderBytes(bts)
				if err != nil {
					err = msgp.WrapError(err, "CountryCallingCode")
					return
				}
				for zb0002 > 0 {
					zb0002--
					field, bts, err = msgp.ReadMapKeyZC(bts)
					if err != nil {
						err = msgp.WrapError(err, "CountryCallingCode")
						return
					}
					switch msgp.UnsafeString(field) {
					case "values":
						var zb0003 uint32
						zb0003, bts, err = msgp.ReadArrayHeaderBytes(bts)
						if err != nil {
							err = msgp.WrapError(err, "CountryCallingCode", "Values")
							return
						}
						if cap(z.CountryCallingCode.Values) >= int(zb0003) {
							z.CountryCallingCode.Values = (z.CountryCallingCode.Values)[:zb0003]
						} else {
							z.CountryCallingCode.Values = make([]string, zb0003)
						}
						for za0001 := range z.CountryCallingCode.Values {
							z.CountryCallingCode.Values[za0001], bts, err = msgp.ReadStringBytes(bts)
							if err != nil {
								err = msgp.WrapError(err, "CountryCallingCode", "Values", za0001)
								return
							}
						}
					case "default":
						z.CountryCallingCode.Default, bts, err = msgp.ReadStringBytes(bts)
						if err != nil {
							err = msgp.WrapError(err, "CountryCallingCode", "Default")
							return
						}
					default:
						bts, err = msgp.Skip(bts)
						if err != nil {
							err = msgp.WrapError(err, "CountryCallingCode")
							return
						}
					}
				}
			}
		case "metadata":
			var zb0004 uint32
			zb0004, bts, err = msgp.ReadMapHeaderBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Metadata")
				return
			}
			if z.Metadata == nil {
				z.Metadata = make(AuthUIMetadataConfiguration, zb0004)
			} else if len(z.Metadata) > 0 {
				for key := range z.Metadata {
					delete(z.Metadata, key)
				}
			}
			for zb0004 > 0 {
				var za0002 string
				var za0003 interface{}
				zb0004--
				za0002, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					err = msgp.WrapError(err, "Metadata")
					return
				}
				za0003, bts, err = msgp.ReadIntfBytes(bts)
				if err != nil {
					err = msgp.WrapError(err, "Metadata", za0002)
					return
				}
				z.Metadata[za0002] = za0003
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				err = msgp.WrapError(err)
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *AuthUIConfiguration) Msgsize() (s int) {
	s = 1 + 4 + msgp.StringPrefixSize + len(z.CSS) + 21
	if z.CountryCallingCode == nil {
		s += msgp.NilSize
	} else {
		s += 1 + 7 + msgp.ArrayHeaderSize
		for za0001 := range z.CountryCallingCode.Values {
			s += msgp.StringPrefixSize + len(z.CountryCallingCode.Values[za0001])
		}
		s += 8 + msgp.StringPrefixSize + len(z.CountryCallingCode.Default)
	}
	s += 9 + msgp.MapHeaderSize
	if z.Metadata != nil {
		for za0002, za0003 := range z.Metadata {
			_ = za0003
			s += msgp.StringPrefixSize + len(za0002) + msgp.GuessSize(za0003)
		}
	}
	return
}

// DecodeMsg implements msgp.Decodable
func (z *AuthUICountryCallingCodeConfiguration) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zb0001 uint32
	zb0001, err = dc.ReadMapHeader()
	if err != nil {
		err = msgp.WrapError(err)
		return
	}
	for zb0001 > 0 {
		zb0001--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		switch msgp.UnsafeString(field) {
		case "values":
			var zb0002 uint32
			zb0002, err = dc.ReadArrayHeader()
			if err != nil {
				err = msgp.WrapError(err, "Values")
				return
			}
			if cap(z.Values) >= int(zb0002) {
				z.Values = (z.Values)[:zb0002]
			} else {
				z.Values = make([]string, zb0002)
			}
			for za0001 := range z.Values {
				z.Values[za0001], err = dc.ReadString()
				if err != nil {
					err = msgp.WrapError(err, "Values", za0001)
					return
				}
			}
		case "default":
			z.Default, err = dc.ReadString()
			if err != nil {
				err = msgp.WrapError(err, "Default")
				return
			}
		default:
			err = dc.Skip()
			if err != nil {
				err = msgp.WrapError(err)
				return
			}
		}
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z *AuthUICountryCallingCodeConfiguration) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 2
	// write "values"
	err = en.Append(0x82, 0xa6, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73)
	if err != nil {
		return
	}
	err = en.WriteArrayHeader(uint32(len(z.Values)))
	if err != nil {
		err = msgp.WrapError(err, "Values")
		return
	}
	for za0001 := range z.Values {
		err = en.WriteString(z.Values[za0001])
		if err != nil {
			err = msgp.WrapError(err, "Values", za0001)
			return
		}
	}
	// write "default"
	err = en.Append(0xa7, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74)
	if err != nil {
		return
	}
	err = en.WriteString(z.Default)
	if err != nil {
		err = msgp.WrapError(err, "Default")
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *AuthUICountryCallingCodeConfiguration) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 2
	// string "values"
	o = append(o, 0x82, 0xa6, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73)
	o = msgp.AppendArrayHeader(o, uint32(len(z.Values)))
	for za0001 := range z.Values {
		o = msgp.AppendString(o, z.Values[za0001])
	}
	// string "default"
	o = append(o, 0xa7, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74)
	o = msgp.AppendString(o, z.Default)
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *AuthUICountryCallingCodeConfiguration) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zb0001 uint32
	zb0001, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		err = msgp.WrapError(err)
		return
	}
	for zb0001 > 0 {
		zb0001--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		switch msgp.UnsafeString(field) {
		case "values":
			var zb0002 uint32
			zb0002, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Values")
				return
			}
			if cap(z.Values) >= int(zb0002) {
				z.Values = (z.Values)[:zb0002]
			} else {
				z.Values = make([]string, zb0002)
			}
			for za0001 := range z.Values {
				z.Values[za0001], bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					err = msgp.WrapError(err, "Values", za0001)
					return
				}
			}
		case "default":
			z.Default, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Default")
				return
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				err = msgp.WrapError(err)
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *AuthUICountryCallingCodeConfiguration) Msgsize() (s int) {
	s = 1 + 7 + msgp.ArrayHeaderSize
	for za0001 := range z.Values {
		s += msgp.StringPrefixSize + len(z.Values[za0001])
	}
	s += 8 + msgp.StringPrefixSize + len(z.Default)
	return
}

// DecodeMsg implements msgp.Decodable
func (z *AuthUIMetadataConfiguration) DecodeMsg(dc *msgp.Reader) (err error) {
	var zb0003 uint32
	zb0003, err = dc.ReadMapHeader()
	if err != nil {
		err = msgp.WrapError(err)
		return
	}
	if (*z) == nil {
		(*z) = make(AuthUIMetadataConfiguration, zb0003)
	} else if len((*z)) > 0 {
		for key := range *z {
			delete((*z), key)
		}
	}
	for zb0003 > 0 {
		zb0003--
		var zb0001 string
		var zb0002 interface{}
		zb0001, err = dc.ReadString()
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		zb0002, err = dc.ReadIntf()
		if err != nil {
			err = msgp.WrapError(err, zb0001)
			return
		}
		(*z)[zb0001] = zb0002
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z AuthUIMetadataConfiguration) EncodeMsg(en *msgp.Writer) (err error) {
	err = en.WriteMapHeader(uint32(len(z)))
	if err != nil {
		err = msgp.WrapError(err)
		return
	}
	for zb0004, zb0005 := range z {
		err = en.WriteString(zb0004)
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		err = en.WriteIntf(zb0005)
		if err != nil {
			err = msgp.WrapError(err, zb0004)
			return
		}
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z AuthUIMetadataConfiguration) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	o = msgp.AppendMapHeader(o, uint32(len(z)))
	for zb0004, zb0005 := range z {
		o = msgp.AppendString(o, zb0004)
		o, err = msgp.AppendIntf(o, zb0005)
		if err != nil {
			err = msgp.WrapError(err, zb0004)
			return
		}
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *AuthUIMetadataConfiguration) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var zb0003 uint32
	zb0003, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		err = msgp.WrapError(err)
		return
	}
	if (*z) == nil {
		(*z) = make(AuthUIMetadataConfiguration, zb0003)
	} else if len((*z)) > 0 {
		for key := range *z {
			delete((*z), key)
		}
	}
	for zb0003 > 0 {
		var zb0001 string
		var zb0002 interface{}
		zb0003--
		zb0001, bts, err = msgp.ReadStringBytes(bts)
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		zb0002, bts, err = msgp.ReadIntfBytes(bts)
		if err != nil {
			err = msgp.WrapError(err, zb0001)
			return
		}
		(*z)[zb0001] = zb0002
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z AuthUIMetadataConfiguration) Msgsize() (s int) {
	s = msgp.MapHeaderSize
	if z != nil {
		for zb0004, zb0005 := range z {
			_ = zb0005
			s += msgp.StringPrefixSize + len(zb0004) + msgp.GuessSize(zb0005)
		}
	}
	return
}
