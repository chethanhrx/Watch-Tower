package com.watchtower.detection.config;

import com.watchtower.common.event.NormalizedLogEvent;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.support.serializer.JsonDeserializer;

import java.util.Map;

@Configuration
public class KafkaConsumerConfig {

    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;

    @Bean
    public ConsumerFactory<String, NormalizedLogEvent> logEventConsumerFactory() {
        JsonDeserializer<NormalizedLogEvent> deserializer = new JsonDeserializer<>(NormalizedLogEvent.class);
        deserializer.setRemoveTypeHeaders(true);
        deserializer.addTrustedPackages("com.watchtower.*");
        deserializer.setUseTypeMapperForKey(false);

        return new DefaultKafkaConsumerFactory<>(
                Map.of(
                        ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers,
                        ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "latest",
                        ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, true
                ),
                new StringDeserializer(),
                deserializer
        );
    }

    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, NormalizedLogEvent> logEventListenerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, NormalizedLogEvent> factory =
                new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(logEventConsumerFactory());
        factory.setConcurrency(3); // Match partition count for parallelism
        return factory;
    }
}
