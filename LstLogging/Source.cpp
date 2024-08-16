#include "LstLogger.h"

using namespace Lst;

int main() {
    Logger logger(Logger::LogLevel::Trace);

    logger.log("This is a TRACE log", Logger::LogLevel::Trace);
    logger.log("This is a DEBUG log", Logger::LogLevel::Debug);
    logger.log("This is an INFO log", Logger::LogLevel::Info);
    logger.log("This is a WARNING log", Logger::LogLevel::Warning);
    logger.log("This is an ERROR log", Logger::LogLevel::Error);
    logger.log("This is a CRITICAL log", Logger::LogLevel::Critical);
    logger.log("This is a FATAL log", Logger::LogLevel::Fatal);

    return 0;
}