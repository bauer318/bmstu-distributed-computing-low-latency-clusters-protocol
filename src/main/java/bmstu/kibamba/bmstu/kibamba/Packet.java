package bmstu.kibamba.bmstu.kibamba;

import java.nio.ByteBuffer;
import java.util.zip.CRC32;

public class Packet {
    private final byte version;
    private final byte messageType;
    private final short messageId;
    private final short payloadLength;
    private final byte[] payload;
    private final short checksum;

    public Packet(byte version, byte messageType, short messageId, byte[] payload) {
        this.version = version;
        this.messageType = messageType;
        this.messageId = messageId;
        this.payload = payload;
        this.payloadLength = (short) payload.length;
        this.checksum = calculateChecksum();
    }

    // Сериализация пакета в байтовый массив
    public byte[] toBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(8 + payload.length);
        buffer.put(version);
        buffer.put(messageType);
        buffer.putShort(messageId);
        buffer.putShort(payloadLength);
        buffer.put(payload);
        buffer.putShort(checksum);
        return buffer.array();
    }

    // Десериализация байтового массива в объект Packet
    public static Packet fromBytes(byte[] data) {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        byte version = buffer.get();
        byte messageType = buffer.get();
        short messageId = buffer.getShort();
        short payloadLength = buffer.getShort();
        byte[] payload = new byte[payloadLength];
        buffer.get(payload);
        short checksum = buffer.getShort();

        Packet packet = new Packet(version, messageType, messageId, payload);
        if (packet.checksum != checksum) {
            throw new IllegalArgumentException("Invalid checksum");
        }
        return packet;
    }

    // Расчёт контрольной суммы
    private short calculateChecksum() {
        CRC32 crc = new CRC32();
        crc.update(toBytesWithoutChecksum());
        return (short) crc.getValue();
    }

    // Получить байты без контрольной суммы
    private byte[] toBytesWithoutChecksum() {
        ByteBuffer buffer = ByteBuffer.allocate(6 + payload.length);
        buffer.put(version);
        buffer.put(messageType);
        buffer.putShort(messageId);
        buffer.putShort(payloadLength);
        buffer.put(payload);
        return buffer.array();
    }

    // Геттеры
    public byte getVersion() { return version; }
    public byte getMessageType() { return messageType; }
    public short getMessageId() { return messageId; }
    public byte[] getPayload() { return payload; }
}

