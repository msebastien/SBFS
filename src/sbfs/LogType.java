package sbfs;

import java.util.HashMap;
import java.util.Map;

public enum LogType {
    INFO(0), SERVER(1), CLIENT(2), DATA(3);

    private final int value;
    LogType(int value) {
        this.value = value;
    }

    public int getValue(){
        return this.value;
    }

    private static final Map<Integer, LogType> _map = new HashMap<>();
    static
    {
        for (LogType request : LogType.values())
            _map.put(request.value, request);
    }

    /**
     * Get Log type from value
     * @param value Value
     * @return LogType
     */
    public static LogType from(int value)
    {
        return _map.get(value);
    }
}
