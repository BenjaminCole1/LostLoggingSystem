#pragma once

#include <iostream>
#include <fstream>
#include <mutex>
#include <string>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <queue>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <vector>
#include <cassert>

#ifdef _WIN32
#include <windows.h>
#include <winbase.h>
#else
#include <syslog.h>
#include <unistd.h>
#endif

namespace Lst
{
    class Logger
    {
    public:
        enum class LogLevel
        {
            Trace,
            Debug,
            Info,
            Warning,
            Error,
            Critical,
            Fatal
        };

        Logger(LogLevel logLevel = LogLevel::Info, const std::string& logFile = "", size_t maxFileSize = 10 * 1024 * 1024)
            : currentLogLevel(logLevel), logToFile(!logFile.empty()), logFileName(logFile), stopLogging(false),
            maxFileSize(maxFileSize), currentFileSize(0)
        {
#ifdef _WIN32
            hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
#else
            openlog("LstLogger", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_USER);
#endif
            if (logToFile)
            {
                try {
                    openLogFile();
                }
                catch (const std::runtime_error& e) {
                    std::cerr << "Logger initialization error: " << e.what() << std::endl;
                }
            }

            loggingThread = std::thread(&Logger::processQueue, this);
        }

        ~Logger()
        {
            stopLogging = true;
            condition.notify_all();
            if (loggingThread.joinable())
            {
                loggingThread.join();
            }

            if (logStream.is_open())
            {
                logStream.close();
            }

#ifndef _WIN32
            closelog();
#endif
        }

        void log(const std::string& message, LogLevel level)
        {
            if (level < currentLogLevel)
            {
                return;
            }

            std::string timestamp = getTimestamp();
            std::string fullMessage = "[" + timestamp + "] [" + logLevelToString(level) + "] " + message;

            {
                std::lock_guard<std::mutex> lock(queueMutex);
                logQueue.push(std::make_pair(fullMessage, level));
            }
            condition.notify_one();
        }

        void setLogLevel(LogLevel level)
        {
            currentLogLevel = level;
        }

        LogLevel getLogLevel() const
        {
            return currentLogLevel;
        }

    private:
#ifdef _WIN32
        HANDLE hConsole;
#endif
        std::mutex queueMutex;
        std::mutex logMutex;
        std::condition_variable condition;
        LogLevel currentLogLevel;
        bool logToFile;
        std::string logFileName;
        std::ofstream logStream;
        std::queue<std::pair<std::string, LogLevel>> logQueue;
        std::thread loggingThread;
        std::atomic<bool> stopLogging;
        size_t maxFileSize;
        size_t currentFileSize;

        void openLogFile()
        {
            logStream.open(logFileName, std::ios_base::app);
            if (!logStream.is_open())
            {
                throw std::runtime_error("Unable to open log file: " + logFileName);
            }
            logStream.seekp(0, std::ios::end);
            currentFileSize = logStream.tellp();
        }

        void rotateLogFile()
        {
            logStream.close();
            std::string rotatedFileName = logFileName + "." + getTimestamp();
            std::rename(logFileName.c_str(), rotatedFileName.c_str());
            openLogFile();
        }

        void setColor(LogLevel level)
        {
#ifdef _WIN32
            if (hConsole == INVALID_HANDLE_VALUE) return;
            switch (level)
            {
            case LogLevel::Trace:
            case LogLevel::Debug:
                SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                break;
            case LogLevel::Info:
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                break;
            case LogLevel::Warning:
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                break;
            case LogLevel::Error:
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
                break;
            case LogLevel::Critical:
            case LogLevel::Fatal:
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                break;
            }
#else
            if (!isTerminal()) return;
            switch (level)
            {
            case LogLevel::Trace:
            case LogLevel::Debug:
                std::cout << "\033[34m";
                break;
            case LogLevel::Info:
                std::cout << "\033[32m";
                break;
            case LogLevel::Warning:
                std::cout << "\033[33m";
                break;
            case LogLevel::Error:
                std::cout << "\033[31m";
                break;
            case LogLevel::Critical:
            case LogLevel::Fatal:
                std::cout << "\033[35m";
                break;
            }
#endif
        }

        void resetColor()
        {
#ifdef _WIN32
            if (hConsole != INVALID_HANDLE_VALUE)
            {
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            }
#else
            if (isTerminal())
            {
                std::cout << "\033[0m";
            }
#endif
        }

        std::string getTimestamp() const
        {
            auto now = std::chrono::system_clock::now();
            auto time_t_now = std::chrono::system_clock::to_time_t(now);
            std::tm tm_now;
#ifdef _WIN32
            localtime_s(&tm_now, &time_t_now);
#else
            localtime_r(&tm_now, &time_t_now);
#endif
            std::ostringstream oss;
            oss << (tm_now.tm_year + 1900) << '-'
                << std::setw(2) << std::setfill('0') << (tm_now.tm_mon + 1) << '-'
                << std::setw(2) << std::setfill('0') << tm_now.tm_mday << ' '
                << std::setw(2) << std::setfill('0') << tm_now.tm_hour << ':'
                << std::setw(2) << std::setfill('0') << tm_now.tm_min << ':'
                << std::setw(2) << std::setfill('0') << tm_now.tm_sec;
            return oss.str();
        }

        std::string logLevelToString(LogLevel level) const
        {
            switch (level)
            {
            case LogLevel::Trace:
                return "TRACE";
            case LogLevel::Debug:
                return "DEBUG";
            case LogLevel::Info:
                return "INFO";
            case LogLevel::Warning:
                return "WARNING";
            case LogLevel::Error:
                return "ERROR";
            case LogLevel::Critical:
            case LogLevel::Fatal:
                return "CRITICAL";
            default:
                return "UNKNOWN";
            }
        }

        void processQueue()
        {
            while (!stopLogging)
            {
                std::unique_lock<std::mutex> lock(queueMutex);
                condition.wait_for(lock, std::chrono::seconds(1), [this]() { return !logQueue.empty() || stopLogging; });

                while (!logQueue.empty())
                {
                    auto pair = logQueue.front();
                    auto& fullMessage = pair.first;
                    auto& level = pair.second;
                    logQueue.pop();
                    lock.unlock();

                    {
                        std::lock_guard<std::mutex> logLock(logMutex);
                        setColor(level);
                        std::cout << fullMessage << std::endl;
                        resetColor();

#ifdef _WIN32
                        if (logToFile && logStream.is_open())
                        {
                            logStream << fullMessage << std::endl;
                            currentFileSize += fullMessage.size();
                            if (currentFileSize >= maxFileSize)
                            {
                                rotateLogFile();
                            }
                        }
#else
                        if (logToFile && logStream.is_open())
                        {
                            logStream << fullMessage << std::endl;
                            currentFileSize += fullMessage.size();
                            if (currentFileSize >= maxFileSize)
                            {
                                rotateLogFile();
                            }
                        }
                        else
                        {
                            syslog(getSyslogLevel(level), "%s", fullMessage.c_str());
                        }
#endif
                    }

                    lock.lock();
                }

                if (logToFile && logStream.is_open())
                {
                    logStream.flush();
                }
            }
        }

#ifdef _WIN32
        int getEventLogLevel(LogLevel level) const
        {
            switch (level)
            {
            case LogLevel::Trace:
            case LogLevel::Debug:
            case LogLevel::Info:
                return EVENTLOG_INFORMATION_TYPE;
            case LogLevel::Warning:
                return EVENTLOG_WARNING_TYPE;
            case LogLevel::Error:
            case LogLevel::Critical:
            case LogLevel::Fatal:
                return EVENTLOG_ERROR_TYPE;
            default:
                return EVENTLOG_INFORMATION_TYPE;
            }
        }
#else
        int getSyslogLevel(LogLevel level) const
        {
            switch (level)
            {
            case LogLevel::Trace:
            case LogLevel::Debug:
                return LOG_DEBUG;
            case LogLevel::Info:
                return LOG_INFO;
            case LogLevel::Warning:
                return LOG_WARNING;
            case LogLevel::Error:
                return LOG_ERR;
            case LogLevel::Critical:
            case LogLevel::Fatal:
                return LOG_CRIT;
            default:
                return LOG_INFO;
            }
        }
#endif

#ifndef _WIN32
        bool isTerminal() const
        {
            return isatty(fileno(stdout));
        }
#endif
    };
}
