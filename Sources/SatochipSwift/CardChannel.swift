public protocol CardChannel {
    var connected: Bool { get }
    func send(_ cmd: APDUCommand) throws -> APDUResponse
}
