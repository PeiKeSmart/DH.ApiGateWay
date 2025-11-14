using System.Buffers;

namespace DH.ApiGateWay.Util;

internal ref struct ValueStringBuilder
{
    private Span<char> _chars;
    private char[]? _arrayToReturnToPool;
    private int _pos;

    public ValueStringBuilder(Span<char> initialBuffer)
    {
        _arrayToReturnToPool = null;
        _chars = initialBuffer;
        _pos = 0;
    }

    public int Length => _pos;

    public void Append(char value)
    {
        if (_pos >= _chars.Length)
        {
            Grow(1);
        }

        _chars[_pos++] = value;
    }

    public void Append(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return;
        }

        Append(value.AsSpan());
    }

    public void Append(ReadOnlySpan<char> value)
    {
        if (value.Length == 0)
        {
            return;
        }

        var newLength = _pos + value.Length;
        if (newLength > _chars.Length)
        {
            Grow(value.Length);
        }

        value.CopyTo(_chars.Slice(_pos));
        _pos = newLength;
    }

    public ReadOnlySpan<char> AsSpan()
    {
        return _chars.Slice(0, _pos);
    }

    public override string ToString()
    {
        return new string(_chars.Slice(0, _pos));
    }

    public void Dispose()
    {
        var array = _arrayToReturnToPool;
        if (array != null)
        {
            _arrayToReturnToPool = null;
            ArrayPool<char>.Shared.Return(array);
        }

        _chars = Span<char>.Empty;
        _pos = 0;
    }

    private void Grow(int additionalCapacity)
    {
        var currentLength = _chars.Length;
        var desiredLength = Math.Max(currentLength * 2, currentLength + additionalCapacity);
        if (desiredLength <= 0)
        {
            desiredLength = Math.Max(256, additionalCapacity);
        }

        var previousArray = _arrayToReturnToPool;
        var newArray = ArrayPool<char>.Shared.Rent(desiredLength);
        _chars.Slice(0, _pos).CopyTo(newArray);
        _chars = _arrayToReturnToPool = newArray;
        if (previousArray != null)
        {
            ArrayPool<char>.Shared.Return(previousArray);
        }
    }
}
