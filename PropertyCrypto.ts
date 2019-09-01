import { crypto } from "./crypto"
import * as Base64 from "./Base64"
import { Payload } from "./Payload"
import { TextEncoder } from "./TextEncoder"
import { TextDecoder } from "./TextDecoder"

export class PropertyCrypto {
	protected readonly encoder = new TextEncoder()
	protected readonly decoder = new TextDecoder()
	private properties: string[][]
	private constructor(private secret: string, ...properties: string[]) {
		this.properties = properties.map(p => p.split("."))
	}
	encrypt(payload: Payload): Promise<Payload> {
		return this.process(payload, value => this.encoder.encode(JSON.stringify(value)), value => Base64.encode(value, "url"))
	}
	decrypt(payload: Payload): Promise<Payload> {
		return this.process(payload, value => typeof(value) == "string" ? Base64.decode(value, "url") : new Uint8Array(), value => JSON.parse(this.decoder.decode(value)))
	}
	private async process(payload: Payload, preprocess: (value: any) => Uint8Array, postprocess: (value: Uint8Array) => any): Promise<Payload> {
		const secret = this.secret + payload.sub + payload.iat
		for (const property of this.properties)
			payload = await this.processProperty(payload, property, secret + property.join("."), preprocess, postprocess)
		return payload
	}
	private async processProperty(payload: Payload, property: string[], secret: string, preprocess: (value: any) => Uint8Array, postprocess: (value: Uint8Array) => any): Promise<Payload> {
		const result = { ...payload }
		if (result[property[0]])
			if (property.length == 1) {
				const data = preprocess(payload[property[0]])
				const key = new Uint8Array(await crypto.subtle.digest("SHA-512", this.encoder.encode(secret)))
				const processed = new Uint8Array(data.length)
				for (let index = 0; index < data.length; index++)
					// tslint:disable-next-line:no-bitwise
					processed[index] = data[index] ^ key[index]
				result[property[0]] = postprocess(processed)
			} else
				result[property[0]] = await this.processProperty(result[property[0]] as Payload, property.slice(1), secret, preprocess, postprocess)
		return result
	}
	static create(secret: string, ...properties: string[]): PropertyCrypto
	static create(secret: string | undefined, ...properties: string[]): PropertyCrypto | undefined
	static create(secret: string | undefined, ...properties: string[]): PropertyCrypto | undefined {
		return secret && new PropertyCrypto(secret, ...properties) || undefined
	}
}
