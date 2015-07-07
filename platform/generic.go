//+build !linux

package platform

func InstallChildSa(sa *SaParams) error {
	return nil
}

func RemoveChildSa(sa *SaParams) error {
	return nil
}
