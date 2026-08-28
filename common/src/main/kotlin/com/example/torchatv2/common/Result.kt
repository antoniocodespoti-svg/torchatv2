package com.example.torchatv2.common

sealed class AppResult<out T> {
    data class Success<out T>(val data: T) : AppResult<T>()
    data class Failure(val error: Exception) : AppResult<Nothing>()
}
