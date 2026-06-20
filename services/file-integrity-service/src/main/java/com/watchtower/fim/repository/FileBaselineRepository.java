package com.watchtower.fim.repository;

import com.watchtower.fim.entity.FileBaseline;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface FileBaselineRepository extends JpaRepository<FileBaseline, Long> {
    Optional<FileBaseline> findByFilePath(String filePath);
}
