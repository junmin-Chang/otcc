add(x, y)
{
    return x + y;
}
mul(x, y)
{
    return x * y;
}
main() 
{
    int a;
    a = 13;

    a = add(a,3);
    a = compute(a);
    return a;
}

compute(n)
{
    return mul(n,2);
}
