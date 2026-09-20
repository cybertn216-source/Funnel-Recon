// The banner is presentation only: edit it without touching scan behavior.
package banner

import "github.com/pterm/pterm"

func Print() {

	pterm.Println(pterm.FgLightCyan.Sprint(`
  ______                      _ ____
 |  ____|                    | |  _ \\
 | |__ _   _ _ __  _ __   ___| | |_) |___  ___ ___  _ __
 |  __| | | | '_ \\| '_ \\ / _ \\ |  _ </ _ \\/ __/ _ \\| '_ \\
 | |  | |_| | | | | | | |  __/ | | \\ |  __/ (_| (_) | | | |
 |_|   \\__,_|_| |_|_| |_|\\___|_|_|  \\_\\___|\\___\\___/|_| |_|
`))
	pterm.Println(pterm.FgLightCyan.Sprint("          Created by: SydneySpider"))
	pterm.Info.Println("Authorized reconnaissance • unverified findings only")
}
