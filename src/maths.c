float newtonian_sqrt(float x, float precision)
{
    float   guess;
    float   guess_squared;
    float   new_guess;

    guess = x / 2;
    guess_squared = guess * guess;
    while (guess_squared - x > precision || x - guess_squared > precision)
    {
        new_guess = (guess + x / guess) / 2;
        guess = new_guess;
        guess_squared = guess * guess;
    }
    return guess;
}

float pow_2(float x)
{
    return x * x;
}

float fractional_percentage(float numerator, float denominator)
{
    return (numerator / denominator) * 100.0;
}
